import crypto from 'node:crypto';
import base32 from 'hi-base32';

/**
 * Generate a unique base 32 encoded secret for 2FA.
 * @param {number} size - Secret size in bytes.
 * @returns {string} Base32 encoded secret.
 */
export default function generateSecret(size = 20) {
	return base32.encode(crypto.randomBytes(size));
}
