<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Exception;
use JsonSerializable;
use Throwable;

abstract class SecurityTxtFetcherException extends Exception implements JsonSerializable
{

	/**
	 * @param list<mixed> $constructorParams
	 * @param list<string|int> $messageValues
	 */
	public function __construct(
		private readonly array $constructorParams,
		private readonly string $messageFormat,
		private readonly array $messageValues,
		private readonly string $url,
		int $code = 0,
		?Throwable $previous = null,
	) {
		parent::__construct(vsprintf($this->messageFormat, $this->messageValues), $code, $previous);
	}


	public function getMessageFormat(): string
	{
		return $this->messageFormat;
	}


	/**
	 * @return list<string|int>
	 */
	public function getMessageValues(): array
	{
		return $this->messageValues;
	}


	public function getUrl(): string
	{
		return $this->url;
	}


	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'class' => $this::class,
			'params' => $this->constructorParams,
			'message' => $this->getMessage(),
			'messageFormat' => $this->getMessageFormat(),
			'messageValues' => $this->getMessageValues(),
			'url' => $this->getUrl(),
		];
	}

}
