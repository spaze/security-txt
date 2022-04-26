<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Exception;
use Throwable;

abstract class SecurityTxtException extends Exception
{

	public function __construct(
		string $message,
		private readonly string $url,
		int $code = 0,
		?Throwable $previous = null,
	) {
		parent::__construct($message, $code, $previous);
	}


	public function getUrl(): string
	{
		return $this->url;
	}

}
