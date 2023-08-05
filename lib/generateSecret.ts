import crypto from 'node:crypto';
import base32 from 'hi-base32';

/**
 *
 * @param {Number} size - Secret size in bytes.
 * @returns {String} Base32 encoded secret.
 */
export default function generateSecret(size = 20) {
	return base32.encode(crypto.randomBytes(size));
}
