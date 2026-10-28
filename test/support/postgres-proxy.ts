import net, { type Socket } from 'node:net';

interface ConnectionState {
  client: Socket;
  upstream: Socket;
  clientBuffer: Buffer;
  serverBuffer: Buffer;
  startupComplete: boolean;
  droppingCommitReply: boolean;
}

function parseRegularMessages(buffer: Buffer): { messages: Buffer[]; rest: Buffer[]; readyForQuery: boolean } {
  const messages: Buffer[] = [];
  let offset = 0;
  let readyForQuery = false;
  while (offset + 5 <= buffer.length) {
    const length = buffer.readInt32BE(offset + 1);
    if (length < 4) throw new Error('Invalid PostgreSQL frame');
    const total = 1 + length;
    if (offset + total > buffer.length) break;
    const message = buffer.subarray(offset, offset + total);
    messages.push(message);
    if (message[0] === 0x5a) readyForQuery = true;
    offset += total;
  }
  return { messages, rest: [buffer.subarray(offset)], readyForQuery };
}

export class CommitAckDropProxy {
  private server?: net.Server;
  private armed = false;
  private droppedResolve?: () => void;
  private droppedPromise?: Promise<void>;
  private readonly sockets = new Set<Socket>();
  public port = 0;

  async start(targetHost: string, targetPort: number): Promise<void> {
    this.server = net.createServer((client) => {
      const upstream = net.connect(targetPort, targetHost);
      const state: ConnectionState = {
        client, upstream, clientBuffer: Buffer.alloc(0), serverBuffer: Buffer.alloc(0),
        startupComplete: false, droppingCommitReply: false,
      };
      this.sockets.add(client);
      this.sockets.add(upstream);
      const remove = () => { this.sockets.delete(client); this.sockets.delete(upstream); };
      client.on('data', (chunk) => this.forwardClientBytes(state, chunk));
      upstream.on('data', (chunk) => this.forwardServerBytes(state, chunk));
      client.on('error', () => undefined);
      upstream.on('error', () => undefined);
      client.on('close', remove);
      upstream.on('close', remove);
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(0, '127.0.0.1', () => resolve());
    });
    this.port = (this.server.address() as net.AddressInfo).port;
  }

  armNextCommitAckDrop(): Promise<void> {
    if (this.armed) throw new Error('Commit-ack fault already armed');
    this.armed = true;
    this.droppedPromise = new Promise<void>((resolve) => { this.droppedResolve = resolve; });
    return this.droppedPromise;
  }

  private forwardClientBytes(state: ConnectionState, chunk: Buffer): void {
    if (!state.startupComplete) {
      state.clientBuffer = Buffer.concat([state.clientBuffer, chunk]);
      if (state.clientBuffer.length < 4) return;
      const startupLength = state.clientBuffer.readInt32BE(0);
      if (state.clientBuffer.length < startupLength) return;
      const startup = state.clientBuffer.subarray(0, startupLength);
      state.upstream.write(startup);
      state.clientBuffer = state.clientBuffer.subarray(startupLength);
      state.startupComplete = true;
      if (state.clientBuffer.length === 0) return;
      chunk = state.clientBuffer;
      state.clientBuffer = Buffer.alloc(0);
    }
    state.clientBuffer = Buffer.concat([state.clientBuffer, chunk]);
    let offset = 0;
    while (offset + 5 <= state.clientBuffer.length) {
      const length = state.clientBuffer.readInt32BE(offset + 1);
      if (length < 4) break;
      const total = 1 + length;
      if (offset + total > state.clientBuffer.length) break;
      const type = state.clientBuffer[offset]!;
      const message = state.clientBuffer.subarray(offset, offset + total);
      if (this.armed && type === 0x51) {
        const query = message.subarray(5).toString('utf8').replace(/\0+$/, '').trim();
        if (/^COMMIT\s*;?$/i.test(query)) {
          this.armed = false;
          state.droppingCommitReply = true;
        }
      }
      state.upstream.write(message);
      offset += total;
    }
    state.clientBuffer = state.clientBuffer.subarray(offset);
  }

  private forwardServerBytes(state: ConnectionState, chunk: Buffer): void {
    if (!state.droppingCommitReply) {
      state.client.write(chunk);
      return;
    }
    state.serverBuffer = Buffer.concat([state.serverBuffer, chunk]);
    const parsed = parseRegularMessages(state.serverBuffer);
    if (!parsed.readyForQuery) return;
    state.serverBuffer = Buffer.alloc(0);
    this.droppedResolve?.();
    state.client.destroy();
    state.upstream.destroy();
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()));
  }
}
