<?php
namespace Daimoonis;

use RobRichards\XMLSecLibs;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Soap security header
 */
class WSSESoap {

	const WSSENS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
	const WSUNS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
	const WSSEPFX = 'wsse';
	const WSUPFX = 'wsu';
	const XMLNS = 'xmlns';
	const defExpires = 600; //v sekundach
	///////////////
	const ERR_NO_SIGNATURE = 80;
	const ERR_PARSE_CERTIFICATE = 81;

	private $certificatePath;
	private $certificateInfo;
	private $soapNS, $soapPFX;
	private $soapDoc = NULL;
	private $envelope = NULL;
	private $SOAPXPath = NULL;
	private $secNode = NULL;
	public $signAllHeaders = FALSE;
	protected static $aErrors = array(
		WSSESoap::ERR_NO_SIGNATURE => 'Nenalezen podpis v requestu',
		WSSESoap::ERR_PARSE_CERTIFICATE => 'Nepodařilo se parsovat certifikát'
	);

	function __construct($doc, $certificatePath, $bMustUnderstand = true) {
		$this->soapDoc = $doc;
		$this->envelope = $doc->documentElement;
		$this->soapNS = $this->envelope->namespaceURI;
		$this->soapPFX = "soap"; //$this->envelope->prefix;

		$this->SOAPXPath = new DOMXPath($doc);
		$this->SOAPXPath->registerNamespace('wssoap', $this->soapNS);
		$this->SOAPXPath->registerNamespace('wswsse', WSSESoap::WSSENS);

		$this->certificateInfo = openssl_x509_parse($certificatePath);

		if ($this->certificateInfo === false) {
			throw new SoapException(WSSESoap::errorString(WSSESoap::ERR_PARSE_CERTIFICATE), WSSESoap::ERR_PARSE_CERTIFICATE);
		}
		$this->certificatePath = $certificatePath;

		$this->locateSecurityHeader($bMustUnderstand);
	}

	/**
	 * Textovy popis chyby
	 *
	 * @param $iKod int cislo chyby
	 * @return string Popis chyby
	 */
	private static function errorString($iKod) {
		if (isset(WSSESoap::$aErrors[$iKod])) {
			return WSSESoap::$aErrors[$iKod];
		} else {
			return 'Neznámá chyba (' . intval($iKod) . ')';
		}
	}

	private function locateSecurityHeader($bMustUnderstand = TRUE, $setActor = NULL) {
		if ($this->secNode == NULL) {
			$headers = $this->SOAPXPath->query('//wssoap:Envelope/wssoap:Header');
			$header = $headers->item(0);
			if (!$header) {
				$header = $this->soapDoc->createElementNS($this->soapNS, $this->soapPFX . ':Header');
				$this->envelope->insertBefore($header, $this->envelope->firstChild);
			}
			$secnodes = $this->SOAPXPath->query('./wswsse:Security', $header);
			$secnode = NULL;
			foreach ($secnodes AS $node) {
				$actor = $node->getAttributeNS($this->soapNS, 'actor');
				if ($actor == $setActor) {
					$secnode = $node;
					break;
				}
			}
			if (!$secnode) {
				$secnode = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':Security');
				$header->appendChild($secnode);
				if ($bMustUnderstand) {
					$secnode->setAttributeNS($this->soapNS, $this->soapPFX . ':mustUnderstand', '1');
				}
				if (!empty($setActor)) {
					$secnode->setAttributeNS($this->soapNS, $this->soapPFX . ':actor', $setActor);
				}
			}
			$this->secNode = $secnode;
		}
		return $this->secNode;
	}

	public function addTimestamp($secondsToExpire = WSSESoap::defExpires) {
		/* Add the WSU timestamps */
		$security = $this->locateSecurityHeader();

		$timestamp = $this->soapDoc->createElementNS(WSSESoap::WSUNS, WSSESoap::WSUPFX . ':Timestamp');
		$security->insertBefore($timestamp, $security->firstChild);
		$currentTime = time();
		$created = $this->soapDoc->createElementNS(WSSESoap::WSUNS, WSSESoap::WSUPFX . ':Created', gmdate("Y-m-d\TH:i:s", $currentTime) . 'Z');
		$timestamp->appendChild($created);
		if (!is_null($secondsToExpire)) {
			$expire = $this->soapDoc->createElementNS(WSSESoap::WSUNS, WSSESoap::WSUPFX . ':Expires', gmdate("Y-m-d\TH:i:s", $currentTime + $secondsToExpire) . 'Z');
			$timestamp->appendChild($expire);
		}
	}

	public function addX509KeyInfo() {
		$objXMLSecDSig = new XMLSecurityDSig();

		if (($objDSig = $objXMLSecDSig->locateSignature($this->soapDoc))) {
			$this->SOAPXPath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
			$query = "./secdsig:KeyInfo";
			$nodeset = $this->SOAPXPath->query($query, $objDSig);
			$keyInfo = $nodeset->item(0);
			if (!$keyInfo) {
				$keyInfo = $objXMLSecDSig->createNewSignNode('KeyInfo');
				$objDSig->appendChild($keyInfo);
			}
			//$keyInfo->setAttribute("Id","keyinfo");
			//$keyInfo->setIdAttribute("Id",true);

			$tokenRef = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':SecurityTokenReference');
			$tokenRef->setAttribute("wsu", WSSESoap::WSUNS);
			//$tokenRef->setAttribute("Id","sectokenref");
			//$tokenRef->setIdAttribute("Id",true);            
			$keyInfo->appendChild($tokenRef);

			$x509Data = $objXMLSecDSig->createNewSignNode('X509Data');
			$tokenRef->appendChild($x509Data);

			$x509IssuerSerial = $objXMLSecDSig->createNewSignNode('X509IssuerSerial');
			$x509Data->appendChild($x509IssuerSerial);
			//jmeno vydavatele soukromeho certifikatu
			$x509IssuerName = $objXMLSecDSig->createNewSignNode('X509IssuerName', $this->certificateInfo['name']);
			$x509IssuerSerial->appendChild($x509IssuerName);
			//seriove cislo soukromeho certifikatu
			$x509SerialNumber = $objXMLSecDSig->createNewSignNode('X509SerialNumber', $this->certificateInfo['serialNumber']);
			$x509IssuerSerial->appendChild($x509SerialNumber);
		} else {
			throw new SoapException(WSSESoap::errorString(WSSESoap::ERR_NO_SIGNATURE), WSSESoap::ERR_NO_SIGNATURE);
		}
	}

	/**
	 * metoda podepsani celeho soap requestu ( reference i telo )
	 */
	public function signSoapDoc($certpass) {
		/**
		 * vytvoreni klice ze soukromeho certifikatu
		 */
		$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array("type" => "private"));
		$objKey->setPassPhrase($certpass);
		$objKey->loadKey($this->certificatePath, true);

		$objDSig = new XMLSecurityDSig();

		$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

		$arNodes = array();
		foreach ($this->secNode->childNodes AS $node) {
			if ($node->nodeType == XML_ELEMENT_NODE) {
				$arNodes[] = $node;
			}
		}

		if ($this->signAllHeaders) {
			foreach ($this->secNode->parentNode->childNodes AS $node) {
				if (($node->nodeType == XML_ELEMENT_NODE) &&
						($node->namespaceURI != WSSESoap::WSSENS)) {
					$arNodes[] = $node;
				}
			}
		}

		foreach ($this->envelope->childNodes AS $node) {
			if ($node->namespaceURI == $this->soapNS && $node->localName == 'Body') {
				$arNodes[] = $node;
				break;
			}
		}

		$arOptions = array('prefix' => WSSESoap::WSUPFX, 'prefix_ns' => WSSESoap::WSUNS);
		$objDSig->addReferenceList($arNodes, XMLSecurityDSig::SHA1, NULL, $arOptions);

		$objDSig->sign($objKey);

		$objDSig->appendSignature($this->secNode, TRUE);
	}

	public function saveXML() {
		return $this->soapDoc->saveXML();
	}

}
