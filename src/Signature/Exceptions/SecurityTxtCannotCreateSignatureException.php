<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Exceptions;

use Spaze\SecurityTxt\Signature\SecurityTxtSignatureErrorInfo;
use Throwable;

final class SecurityTxtCannotCreateSignatureException extends SecurityTxtSignatureException
{

	public function __construct(string $key, SecurityTxtSignatureErrorInfo $errorInfo, ?Throwable $previous = null)
	{
		$message = sprintf(
			'Cannot create a signature using key %s: %s; code: %s, source: %s, library message: %s',
			$key,
			$errorInfo->getMessage() !== false ? $errorInfo->getMessage() : '<false>',
			$errorInfo->getCode(),
			$errorInfo->getSource(),
			$errorInfo->getLibraryMessage(),
		);
		parent::__construct($message, $errorInfo->getCode(), $previous);
	}

}
