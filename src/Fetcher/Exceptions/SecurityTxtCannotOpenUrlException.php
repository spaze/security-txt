<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Throwable;
use ValueError;

final class SecurityTxtCannotOpenUrlException extends SecurityTxtFetcherException
{

	private readonly ?SecurityTxtIpAddressType $ipAddressType;


	/**
	 * @param list<string> $redirects
	 * @param SecurityTxtIpAddressType|value-of<SecurityTxtIpAddressType>|null $ipAddressType An `int` only when rebuilt from JSON, where the wire carries the case value, and
	 *     any other one is refused
	 * @param string|null $error Must not contain anything the checked host controls; `curl_strerror()` is safe, `curl_error()` is not because it quotes strings like the certificate subject name. The console printer encodes values before printing them, so this is not about the terminal: the message also reaches `getMessage()`, the `message` key of the serialized JSON, and whatever a consumer logs, none of which encode anything
	 * @throws ValueError
	 */
	public function __construct(
		string $url,
		array $redirects,
		private readonly ?string $ipAddress = null,
		SecurityTxtIpAddressType|int|null $ipAddressType = null,
		?string $error = null,
		?Throwable $previous = null,
	) {
		$this->ipAddressType = is_int($ipAddressType) ? SecurityTxtIpAddressType::from($ipAddressType) : $ipAddressType;
		$format = "Can't open %s" . $this->getRedirectsFormat($redirects);
		$values = [$url, ...$redirects];
		if ($this->ipAddress !== null) {
			$format .= match ($this->ipAddressType) {
				SecurityTxtIpAddressType::V4 => ' using its IPv4 address %s',
				SecurityTxtIpAddressType::V6 => ' using its IPv6 address %s',
				null => ' using its IP address %s',
			};
			$values[] = $this->ipAddress;
		}
		if ($error !== null) {
			$format .= ' (%s)';
			$values[] = $error;
		}
		parent::__construct(
			[$url, $redirects, $ipAddress, $this->ipAddressType?->value, $error],
			$format,
			$values,
			$url,
			$redirects,
			previous: $previous,
		);
	}


	public function getIpAddress(): ?string
	{
		return $this->ipAddress;
	}


	public function getIpAddressType(): ?SecurityTxtIpAddressType
	{
		return $this->ipAddressType;
	}

}
