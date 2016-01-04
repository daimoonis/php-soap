<?php
namespace Daimoonis;

use \DomDocument;

/**
 * ------------------------------------------
 */
class CustomSoapClient extends SoapClient {

	protected $bSecuritySoap = false;
	private $iMessageExpireAfter = NULL; // v sekundach, pokud je null tak se pouzije defaultni nastaveni wsse soapu

	function __construct($wsdl, $options) {
		parent::__construct($wsdl, $options);
	}

	function __doRequest($request, $location, $action, $version) {

		if ($this->bSecuritySoap) {

			//pokud se jedna o security soap request, pridame do xml requestu patricne security prvky, napriklad:
			//$dom = new DomDocument('1.0', 'UTF-8');
			//$dom->preserveWhiteSpace = false;
			/$dom->loadXML($request);
			//$secureXml = new WSSESoap($dom);

			//if ($this->iMessageExpireAfter)
			//	$secureXml->addTimestamp($this->iMessageExpireAfter);
			//else
			//	$secureXml->addTimestamp();

			//podepsani
			//$secureXml->signAllHeaders = true;
			//$secureXml->signSoapDoc();
			//$secureXml->addX509KeyInfo();

			//$request = $secureXml->saveXML();
		}

		return parent::__doRequest($request, $location, $action, $version);
	}

	/**
	 * void fce nastavi pocet sekund expirace zpravy
	 */
	public function setMessageExpireTime($iSeconds) {
		if (is_int($iSeconds))
			$this->iMessageExpireAfter = $iSeconds;
	}

	/**
	 * void fce nastavi security na true
	 */
	public function setSecurity() {
		$this->bSecuritySoap = true;
	}

	/**
	 * void fce nastavi security na false
	 */
	public function removeSecurity() {
		$this->bSecuritySoap = false;
	}

}
