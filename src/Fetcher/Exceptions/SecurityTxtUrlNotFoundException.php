<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Throwable;
use ValueError;

final class SecurityTxtUrlNotFoundException extends SecurityTxtFetcherException
{

	private readonly SecurityTxtIpAddressType $ipAddressType;


	/**
	 * @param SecurityTxtIpAddressType|value-of<SecurityTxtIpAddressType> $ipAddressType An `int` only when rebuilt from JSON, where the wire carries the case value, and any
	 *     other one is refused. Narrower than the native type on purpose: a replay hands back `mixed`, which this cannot constrain anyway, so the annotation is spent where it
	 *     does work, on a literal typed in by hand here or by a consumer
	 * @throws ValueError
	 */
	public function __construct(
		string $url,
		int $code,
		private readonly string $ipAddress,
		SecurityTxtIpAddressType|int $ipAddressType,
		?Throwable $previous = null,
	) {
		$this->ipAddressType = is_int($ipAddressType) ? SecurityTxtIpAddressType::from($ipAddressType) : $ipAddressType;
		parent::__construct([$url, $code, $ipAddress, $this->ipAddressType->value], 'URL %s not found, code %s', [$url, (string)$code], $url, code: $code, previous: $previous);
	}


	public function getIpAddress(): string
	{
		return $this->ipAddress;
	}


	public function getIpAddressType(): SecurityTxtIpAddressType
	{
		return $this->ipAddressType;
	}

}
