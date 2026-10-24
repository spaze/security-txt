<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

final class SecurityTxtTopLevelPathOnly extends SecurityTxtSpecViolation
{

	/**
	 * @param int|null $wellKnownHttpCode What the /.well-known/ location answered with, when that was an error other than one saying there is no file there
	 */
	public function __construct(?int $wellKnownHttpCode = null)
	{
		if ($wellKnownHttpCode === null) {
			$format = "%s wasn't found under the %s path";
			$values = ['security.txt', '/.well-known/'];
			$howToFixFormat = 'Move the %s file from the top-level location under the %s path and redirect %s to %s';
			$howToFixValues = ['security.txt', '/.well-known/', '/security.txt', '/.well-known/security.txt'];
		} else {
			$format = '%s answered with HTTP code %s, only the top-level %s was found';
			$values = ['/.well-known/security.txt', (string)$wellKnownHttpCode, 'security.txt'];
			$howToFixFormat = 'Make %s available to everyone, a firewall or a bot protection may be what answers instead, and redirect %s to it';
			$howToFixValues = ['/.well-known/security.txt', '/security.txt'];
		}
		parent::__construct(
			func_get_args(),
			$format,
			$values,
			'draft-foudil-securitytxt-02',
			null,
			$howToFixFormat,
			$howToFixValues,
			'3',
		);
	}

}
