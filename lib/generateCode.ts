import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import base32 from 'hi-base32';

/**
 *
 * @param options - Options object or secret string.
 * @param options.secret - Base32 encoded secret.
 * @param options.step - Time step in seconds. Defaults to 30.
 * @param options.length - Code length. Defaults to 6.
 * @param options.algorithm - HMAC algorithm. Defaults to sha1.
 * @returns {String} The 2FA code.
 */
export default function generateCode(options: GenerateCodeOptions | String) {
	const { secret, step, length, algorithm } = getOptions(options);

	const counter = Math.floor(Date.now() / 1000 / step);
	const counterBuffer = Buffer.alloc(8);
	counterBuffer.writeBigUInt64BE(BigInt(counter));

	const key = Buffer.from(base32.decode.asBytes(secret + new Array((8 - secret.length) % 8).fill('=').join('')));
	const hmac = crypto.createHmac(algorithm, key).update(counterBuffer).digest();

	// Refer to RFC 4226 (HOTP) specification: https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
	const offset = hmac[19] & 15;
	const binary =
		((hmac[offset] & 127) << 24) |
		((hmac[offset + 1] & 255) << 16) |
		((hmac[offset + 2] & 255) << 8) |
		(hmac[offset + 3] & 255);

	return `${binary % 1000000}`.padStart(length, '0');
}

function getOptions(options: GenerateCodeOptions | String) {
	const defaultOptions = { step: 30, length: 6, algorithm: 'sha1' };
	if ('secret' in options) return { ...defaultOptions, ...options };
	return { ...defaultOptions, secret: options };
}

export interface GenerateCodeOptions {
	secret: string;
	step?: number;
	length?: number;
	algorithm?: string;
}
