export class ApiError extends Error {
  constructor(message, kind, status, requestId) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind; // 'network' | 'timeout' | 'invalid-input' | 'busy' | 'server' | 'bad-response'
    this.status = status;
    this.requestId = requestId;
  }
}
