import * as crypto from "crypto";
import * as net from "net";

export type PNPMethod = "get" | "post";

export interface PNPRequest {
	method: PNPMethod;
	path: string;
	headers: Record<string, string>;
	body: string;
}

export interface PNPResponse {
	status: Status;
	headers: Record<string, string>;
	body: string;
}

export class PNPConnection {
	private readonly host: string;
	private readonly port: number;
	private socket: net.Socket;
	
	constructor(host: string, port: number) {
		this.host = host;
		this.port = port;
		this.socket = new net.Socket();
	}
	
	connect(): Promise<void> {
		return new Promise((resolve, reject) => {
			this.socket.connect(this.port, this.host, () => {
				console.log(`Connected to ${this.host}:${this.port}`);
				resolve();
			});
			this.socket.on("error", (err) => {
				console.error(`Caught an error ${err.message}`);
				reject();
			});
		});
	}
	
	send(data: Buffer): Promise<void> {
		return new Promise((resolve, reject) => {
			this.socket.write(data, (err) => {
				if (err) {
					console.error(`Caught an error when trying to send a request: ${err.message}`);
					reject();
				} else resolve();
			});
		});
	}
	
	receive(): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			this.socket.once("data", (data) => {
				console.log(`Got a response with length: ${data.length}`);
				resolve(data);
			});
			this.socket.on("error", (err) => {
				console.log(`Caught an error when getting a response: ${err.message}`);
				reject(err);
			});
		});
	}
	
	close(): void {
		this.socket.end();
		console.log("Connection closed");
	}
}

export class PNPEncryption {
	private readonly algorithm: string;
	private readonly key: Buffer;
	private readonly iv: Buffer;
	
	constructor(key: Buffer, iv: Buffer) {
		this.algorithm = "aes-256-cbc";
		this.key = key;
		this.iv = iv;
	}
	
	encrypt(data: string): string {
		let cipher = crypto.createCipheriv(this.algorithm, this.key, this.iv);
		let encrypted = cipher.update(data, "utf-8", "hex");
		encrypted += cipher.final("hex");
		return encrypted;
	}
	
	decrypt(data: Buffer): string {
		let decipher = crypto.createDecipheriv(this.algorithm, this.key, this.iv);
		let decrypted = decipher.update(data.toString("utf-8"), "hex", "utf-8");
		decrypted += decipher.final("utf-8");
		return decrypted;
	}
}

export class PNPClient {
	private connection: PNPConnection;
	private encryption: PNPEncryption;
	
	constructor(host: string, port: number, key: Buffer, iv: Buffer) {
		this.connection = new PNPConnection(host, port);
		this.encryption = new PNPEncryption(key, iv);
	}
	
	async connect() {
		await this.connection.connect();
	}
	
	async sendRequest(request: PNPRequest): Promise<PNPResponse> {
		const data = JSON.stringify(request);
		const encrypted = this.encryption.encrypt(data);
		
		await this.connection.send(Buffer.from(encrypted));
		const responseEncrypted = await this.connection.receive();
		const responseData = this.encryption.decrypt(responseEncrypted);
		
		return JSON.parse(responseData);
	}
	
	close() {
		this.connection.close();
	}
}

export enum Status {
	// 1xx Informational Responses
	Continue = 100,
	SwitchingProtocols = 101,
	Processing = 102,
	EarlyHints = 103,
	
	// 2xx Success Responses
	OK = 200,
	Created = 201,
	Accepted = 202,
	NonAuthoritativeInformation = 203,
	NoContent = 204,
	ResetContent = 205,
	PartialContent = 206,
	MultiStatus = 207,
	AlreadyReported = 208,
	IMUsed = 226,
	
	// 3xx Redirection Messages
	MultipleChoices = 300,
	MovedPermanently = 301,
	Found = 302,
	SeeOther = 303,
	NotModified = 304,
	UseProxy = 305,
	TemporaryRedirect = 307,
	PermanentRedirect = 308,
	
	// 4xx Client Errors
	BadRequest = 400,
	Unauthorized = 401,
	PaymentRequired = 402,
	Forbidden = 403,
	NotFound = 404,
	MethodNotAllowed = 405,
	NotAcceptable = 406,
	ProxyAuthenticationRequired = 407,
	RequestTimeout = 408,
	Conflict = 409,
	Gone = 410,
	LengthRequired = 411,
	PreconditionFailed = 412,
	PayloadTooLarge = 413,
	URITooLong = 414,
	UnsupportedMediaType = 415,
	RangeNotSatisfiable = 416,
	ExpectationFailed = 417,
	ImATeapot = 418,
	MisdirectedRequest = 421,
	UnprocessableEntity = 422,
	Locked = 423,
	FailedDependency = 424,
	TooEarly = 425,
	UpgradeRequired = 426,
	PreconditionRequired = 428,
	TooManyRequests = 429,
	RequestHeaderFieldsTooLarge = 431,
	UnavailableForLegalReasons = 451,
	
	// 5xx Server Errors
	InternalServerError = 500,
	NotImplemented = 501,
	BadGateway = 502,
	ServiceUnavailable = 503,
	GatewayTimeout = 504,
	HTTPVersionNotSupported = 505,
	VariantAlsoNegotiates = 506,
	InsufficientStorage = 507,
	LoopDetected = 508,
	NotExtended = 510,
	NetworkAuthenticationRequired = 511
}