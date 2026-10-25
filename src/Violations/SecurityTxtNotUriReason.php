<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

/**
 * Why a value is not a URI, decided by `SecurityTxtUriValidator` when it refuses one and carried by the violation, so a violation rebuilt from JSON says why without the
 * value being checked again. An enum for the same reason as `SecurityTxtPreferredLanguagesCommonMistakeReason`: the wire carries only the case value, and the format comes
 * from a `match` here, so it cannot be forged.
 */
enum SecurityTxtNotUriReason: string
{

	/**
	 * A violation stored before it carried the reason.
	 */
	case Unspecified = 'unspecified';

	case SchemeMissing = 'scheme-missing';

	case SchemeMissingEmail = 'scheme-missing-email';

	case SchemeMissingPhone = 'scheme-missing-phone';

	case SchemeMissingHostname = 'scheme-missing-hostname';

	case NotRfc3986 = 'not-rfc-3986';

	case HostMissing = 'host-missing';

	case UserInfo = 'user-info';

	case EmptyUserInfo = 'empty-user-info';

	case PortOutOfRange = 'port-out-of-range';

	case InvalidHost = 'invalid-host';

	case NotUrl = 'not-url';


	/**
	 * What follows the value in the message.
	 *
	 * @return literal-string
	 */
	public function getFormat(): string
	{
		return match ($this) {
			self::Unspecified => "isn't a valid URI",
			self::SchemeMissing, self::SchemeMissingEmail, self::SchemeMissingPhone, self::SchemeMissingHostname => "doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
			self::NotRfc3986 => "doesn't follow the URI syntax described in RFC 3986",
			self::HostMissing => 'has no host',
			self::UserInfo => "contains a user name or a password, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
			self::EmptyUserInfo => "has an @ before the host, which RFC 9110 doesn't allow in an HTTP or HTTPS URI",
			self::PortOutOfRange => 'has a port above 65535',
			self::InvalidHost => "has a host that isn't a valid domain name or IP address",
			self::NotUrl => "can't be parsed as a URL",
		};
	}


	/**
	 * @return literal-string
	 */
	public function getHowToFix(): string
	{
		return match ($this) {
			self::Unspecified, self::SchemeMissing, self::NotRfc3986 => 'Use a URI as the value',
			self::SchemeMissingEmail => 'The value looks like an email address, add the "mailto" schema',
			self::SchemeMissingPhone => 'The value looks like a phone number, add the "tel" schema',
			self::SchemeMissingHostname => 'The value looks like a hostname, add the "https" schema',
			self::HostMissing => 'Put // and the host right after the scheme',
			self::UserInfo => 'Remove the user name, the password, and the @ after them',
			self::EmptyUserInfo => 'Remove the @',
			self::PortOutOfRange => 'Use a port number from 0 to 65535, or leave the port out',
			self::InvalidHost => 'Use a domain name or an IP address as the host',
			self::NotUrl => 'Use a URL as the value',
		};
	}

}
