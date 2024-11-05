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
	private debugMode: boolean;
	
	constructor(host: string, port: number, debugMode: boolean) {
		this.host = host;
		this.port = port;
		this.socket = new net.Socket();
		this.debugMode = debugMode;
	}
	
	connect(): Promise<void> {
		return new Promise((resolve, reject) => {
			this.socket.connect(this.port, this.host, () => {
				if (this.debugMode) console.log(`Connected to ${this.host}:${this.port}`);
				resolve();
			});
			this.socket.on("error", (err) => {
				if (this.debugMode) console.log(`Error: ${err.message}`);
				reject(err);
			});
		});
	}
	
	send(data: Buffer): Promise<void> {
		return new Promise((resolve, reject) => {
			this.socket.write(data, (err) => {
				if (err) {
					if (this.debugMode) console.log(`Error: ${err.message}`);
					reject(err);
				} else {
					if (this.debugMode) console.log(`Sent data to ${this.host}:${this.port} (length: ${data.length})`);
					resolve();
				}
			});
		});
	}
	
	receive(): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			this.socket.once("data", (data) => {
				if (this.debugMode) console.log(`Got data from ${this.host}:${this.port} (length: ${data.length})`);
				resolve(data);
			});
			this.socket.on("error", (err) => {
				if (this.debugMode) console.log(`Error: ${err.message}`);
				reject(err);
			});
		});
	}
	
	close(): void {
		this.socket.end();
		if (this.debugMode) console.log("Connection closed");
	}
	
	setDebugMode(mode: boolean) {
		this.debugMode = mode;
	}
}

export class PNPEncryption {
	private readonly algorithm: string;
	private readonly key: Buffer;
	
	constructor() {
		this.algorithm = "aes-256-cbc";
		this.key = crypto.randomBytes(32);
	}
	
	encrypt(data: string): Buffer {
		const iv = crypto.randomBytes(16);
		const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
		let encrypted = cipher.update(data, "utf8", "hex");
		encrypted += cipher.final("hex");
		return Buffer.from(iv.toString("hex") + ":" + encrypted, "utf8");
	}
	
	decrypt(data: Buffer): string {
		const textParts = data.toString().split(":");
		const iv = Buffer.from(textParts.shift()!, "hex");
		const encryptedText = Buffer.from(textParts.join(":"), "hex");
		const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
		const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
		return decrypted.toString("utf8");
	}
}

export class PNP {
	private connection: PNPConnection;
	private encryption: PNPEncryption;
	
	constructor(host: string, port: number, debugMode: boolean) {
		this.connection = new PNPConnection(host, port, debugMode);
		this.encryption = new PNPEncryption();
	}
	
	async connect() {
		await this.connection.connect();
	}
	
	async sendRequest(request: PNPRequest): Promise<PNPResponse> {
		const data = JSON.stringify(request);
		const encrypted = this.encryption.encrypt(data);
		
		await this.connection.send(encrypted);
		const responseEncrypted = await this.connection.receive();
		const responseData = this.encryption.decrypt(responseEncrypted);
		
		return JSON.parse(responseData);
	}
	
	close() {
		this.connection.close();
	}
	
	setDebugMode(mode: boolean) {
		this.connection.setDebugMode(mode);
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