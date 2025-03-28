import hmac
import hashlib
from struct import pack
import binascii


class SP800_108:
	@staticmethod
	def derive_key(key_derivation_key: bytes, purpose) -> bytes:
		label, context = purpose.get_key_derivation_parameters()
		return SP800_108.derive_key_impl(key_derivation_key, label, context, len(key_derivation_key) * 8)

	@staticmethod
	def derive_key_impl(key: bytes, label: bytes, context: bytes, key_length_in_bits: int) -> bytes:
		hmac_sha = hmac.new(key, digestmod=hashlib.sha512)
		key_length_in_bytes = key_length_in_bits // 8

		label = label if label else b''
		context = context if context else b''

		# Construct fixed input data: Counter (4 bytes) || Label || 0x00 || Context || L (4 bytes)
		fixed_input = label + b'\x00' + context + SP800_108.uint32_to_bytes(key_length_in_bits)

		derived_key = bytearray()
		counter = 1

		while len(derived_key) < key_length_in_bytes:
			counter_bytes = SP800_108.uint32_to_bytes(counter)
			data = counter_bytes + fixed_input
			hmac_sha_copy = hmac_sha.copy()
			hmac_result = hmac_sha_copy.update(data)
			derived_key.extend(hmac_sha_copy.digest())
			counter += 1

		return bytes(derived_key[:key_length_in_bytes])

	@staticmethod
	def uint32_to_bytes(value: int) -> bytes:
		return pack(">I", value)


class Purpose:
	def __init__(self, primary_purpose: str, specific_purposes: list):
		self.primary_purpose = primary_purpose
		self.specific_purposes = specific_purposes
		self._derived_key_label = None
		self._derived_key_context = None

	def get_key_derivation_parameters(self):
		if self._derived_key_label is None:
			self._derived_key_label = self.primary_purpose.encode('utf-8')

		if self._derived_key_context is None:
			context_parts = [sp.encode('utf-8') for sp in self.specific_purposes]
			prefix = len(context_parts[0]).to_bytes(1, 'big')
			separator = len(context_parts[1]).to_bytes(1, 'big')
			context_stream = prefix + separator.join(context_parts)
			self._derived_key_context = context_stream

		return self._derived_key_label, self._derived_key_context

