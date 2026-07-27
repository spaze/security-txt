<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotPublicException;

final class SecurityTxtIpAddressValidator
{

	/**
	 * @throws SecurityTxtHostIpAddressInvalidException
	 * @throws SecurityTxtHostIpAddressNotPublicException
	 */
	public function validate(string $ipAddress, SecurityTxtIpAddressType $type, string $host, string $url): void
	{
		$flag = $type === SecurityTxtIpAddressType::V4 ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
		if (filter_var($ipAddress, FILTER_VALIDATE_IP, $flag) === false) {
			throw new SecurityTxtHostIpAddressInvalidException($host, $ipAddress, $type->value, $url);
		}
		if (filter_var($ipAddress, FILTER_VALIDATE_IP, $flag | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_GLOBAL_RANGE) === false) {
			throw new SecurityTxtHostIpAddressNotPublicException($host, $ipAddress, $url);
		}
	}

}
