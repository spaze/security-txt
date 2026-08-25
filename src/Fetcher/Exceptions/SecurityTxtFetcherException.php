<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Exception;
use JsonSerializable;
use Override;
use Spaze\SecurityTxt\SecurityTxtPrintableAscii;
use Throwable;

abstract class SecurityTxtFetcherException extends Exception implements JsonSerializable
{

	/** @var list<string> */
	private readonly array $messageValues;


	/**
	 * @param list<scalar|null|array<array-key, scalar|array<array-key, scalar|list<string>>>> $constructorParams
	 * @param literal-string $messageFormat Never build this from anything the checked host sends, it is used as a format and only the values are encoded when printed
	 * @param array<array-key, string> $messageValues Stored as a list, see the constructor
	 * @param list<string> $redirects
	 * @throws Throwable
	 */
	public function __construct(
		private readonly array $constructorParams,
		private readonly string $messageFormat,
		array $messageValues,
		private readonly string $url,
		private readonly array $redirects = [],
		int $code = 0,
		?Throwable $previous = null,
	) {
		// Code always passes a list, but `SecurityTxtJson` replays whatever the serialized params hold, and a string key there is read as a named argument by the CLI, which
		// spreads these into a call
		$this->messageValues = array_values($messageValues);
		// `Exception::getMessage()` is final, so this is the only place the message can be made safe to display anywhere, terminal, log or page alike; `getMessageValues()`
		// still hands over what the host sent, for a caller that knows what it is rendering into
		parent::__construct(vsprintf($this->messageFormat, array_map(SecurityTxtPrintableAscii::encode(...), $this->messageValues)), $code, $previous);
	}


	/**
	 * @return literal-string
	 */
	public function getMessageFormat(): string
	{
		return $this->messageFormat;
	}


	/**
	 * The ` (redirects: %s → %s)` part of a message, with one placeholder per redirect, empty when there was none.
	 *
	 * @param list<string> $redirects
	 * @param literal-string $suffix Added inside the brackets after the last redirect
	 * @return literal-string
	 */
	protected function getRedirectsFormat(array $redirects, string $suffix = ''): string
	{
		if ($redirects === []) {
			return '';
		}
		$format = ' (redirects: %s';
		for ($i = 1; $i < count($redirects); $i++) {
			$format .= ' → %s';
		}
		return $format . $suffix . ')';
	}


	/**
	 * @return list<string>
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
	 * @return list<string>
	 */
	public function getRedirects(): array
	{
		return $this->redirects;
	}


	/**
	 * @return array<string, mixed>
	 */
	#[Override]
	public function jsonSerialize(): array
	{
		return [
			'class' => $this::class,
			'params' => $this->constructorParams,
			'message' => $this->getMessage(),
			'messageFormat' => $this->getMessageFormat(),
			'messageValues' => $this->getMessageValues(),
			'url' => $this->getUrl(),
			'redirects' => $this->getRedirects(),
		];
	}

}
