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
	 * @param value-of<SecurityTxtIpAddressType>|null $ipAddressType
	 * @param string|null $error Must not contain anything the checked host controls, the message ends up on a terminal where escape sequences are interpreted; `curl_strerror()` is safe, `curl_error()` is not because it quotes strings like the certificate subject name
	 * @throws ValueError
	 */
	public function __construct(
		string $url,
		array $redirects,
		private readonly ?string $ipAddress = null,
		?int $ipAddressType = null,
		?string $error = null,
		?Throwable $previous = null,
	) {
		$this->ipAddressType = $ipAddressType !== null ? SecurityTxtIpAddressType::from($ipAddressType) : null;
		$format = "Can't open %s";
		$values = [$url];
		if ($redirects !== []) {
			$format .= ' (redirects: %s' . str_repeat(' → %s', count($redirects) - 1) . ')';
			$values = array_merge($values, $redirects);
		}
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
			[$url, $redirects, $ipAddress, $ipAddressType, $error],
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
