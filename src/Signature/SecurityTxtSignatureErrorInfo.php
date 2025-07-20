<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

final readonly class SecurityTxtSignatureErrorInfo
{

	public function __construct(
		private string|false $message,
		private int $code,
		private string $source,
		private string $libraryMessage,
	) {
	}


	public function getMessage(): string|false
	{
		return $this->message;
	}


	public function getCode(): int
	{
		return $this->code;
	}


	public function getSource(): string
	{
		return $this->source;
	}


	public function getLibraryMessage(): string
	{
		return $this->libraryMessage;
	}

}
