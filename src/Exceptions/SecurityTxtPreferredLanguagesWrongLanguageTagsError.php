<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtPreferredLanguagesWrongLanguageTagsError extends SecurityTxtError
{

	/**
	 * @param array<int, string> $wrongLanguages
	 */
	public function __construct(array $wrongLanguages, ?Throwable $previous = null)
	{
		$tags = [];
		foreach ($wrongLanguages as $key => $value) {
			$tags[] = "#{$key} `{$value}`";
		}
		$format = count($wrongLanguages) > 1 ? 'The language tags %s seem invalid' : 'The language tag %s seems invalid';
		$message = sprintf($format, implode(', ', $tags));
		parent::__construct(
			$message . ', the `Preferred-Languages` field must contain one or more language tags as defined in RFC 5646',
			'draft-foudil-securitytxt-05',
			null,
			'Use language tags as defined in RFC 5646, which usually means the shortest ISO 639 code like for example `en`',
			'2.5.8',
			previous: $previous,
		);
	}

}
