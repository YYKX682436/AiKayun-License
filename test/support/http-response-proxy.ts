import type { ClientRequest } from 'node:http';
import { createServer, request as httpsRequest, type Server as HttpsServer } from 'node:https';
import type { Socket } from 'node:net';

export class HttpResponseDropProxy {
  private server?: HttpsServer;
  private armed = false;
  private droppedResolve?: () => void;
  private droppedPromise?: Promise<void>;
  private readonly sockets = new Set<Socket>();
  private readonly requests = new Set<ClientRequest>();
  public port = 0;

  async start(targetPort: number, key: Buffer, cert: Buffer): Promise<void> {
    this.server = createServer({ key, cert }, (clientRequest, clientResponse) => {
      const clientSocket = clientRequest.socket;
      const upstream = httpsRequest({
        hostname: '127.0.0.1', port: targetPort, method: clientRequest.method,
        path: clientRequest.url, headers: clientRequest.headers, rejectUnauthorized: false,
      }, (upstreamResponse) => {
        if (this.armed) {
          this.armed = false;
          upstreamResponse.resume();
          clientResponse.destroy();
          this.droppedResolve?.();
          return;
        }
        clientResponse.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(clientResponse);
      });
      this.sockets.add(clientSocket);
      this.requests.add(upstream);
      upstream.on('socket', (socket) => this.sockets.add(socket));
      upstream.on('close', () => this.requests.delete(upstream));
      clientRequest.on('error', () => clientResponse.destroy());
      upstream.on('error', () => clientResponse.destroy());
      clientResponse.on('close', () => this.sockets.delete(clientSocket));
      clientRequest.pipe(upstream);
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(0, '127.0.0.1', () => resolve());
    });
    this.port = (this.server.address() as { port: number }).port;
  }

  armNextResponseDrop(): Promise<void> {
    if (this.armed) throw new Error('HTTP response drop already armed');
    this.armed = true;
    this.droppedPromise = new Promise<void>((resolve) => { this.droppedResolve = resolve; });
    return this.droppedPromise;
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    for (const request of this.requests) request.destroy();
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()));
  }
}
