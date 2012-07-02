<?php

/**
 * @author "Vladimir Reznichenko <kalessil@gmail.com>"
 */

class sfOdnoklassnikiMelody extends sfMelody2
{
    private $privateSecret = '';

    protected function initialize($config)
    {
        $this->setAccessTokenUrl('http://api.odnoklassniki.ru/oauth/token.do?');
        $this->setRequestAuthUrl('http://www.odnoklassniki.ru/oauth/authorize');

        $this->setNamespaces(array(
            'default' => 'http://api.odnoklassniki.ru',
            'api' => 'http://api.odnoklassniki.ru'));

        if (isset($config['scope'])) {
            $this->setAuthParameter('scope', implode(',', $config['scope']));
        }

        $this->privateSecret = $config['private'];
    }

    public function getAccessToken($verifier, $parameters = array())
    {
        $url = $this->getAccessTokenUrl();

        $this->setAccessParameter('client_id', $this->getKey());
        $this->setAccessParameter('client_secret', $this->privateSecret);
        $this->setAccessParameter('code', $verifier);
        $this->setAccessParameter('grant_type', 'authorization_code');

        $this->addAccessParameters($parameters);

        $parameters = http_build_query($this->getAccessParameters(), '', '&') . '&redirect_uri=' . urlencode($this->getCallback());

        $params = $this->call($url, $parameters, 'POST');

        $params = json_decode($params, true);

        $access_token = isset($params['access_token']) ? $params['access_token'] : null;

        if (is_null($access_token)) {
            $error = sprintf('{OAuth} access token failed - %s returns %s', $this->getName(), print_r($params, true));
            sfContext::getInstance()->getLogger()->err($error);
        } else {
            $sig = md5("application_key={$this->getKey()}method=users.getCurrentUser" . md5($access_token . $this->privateSecret));
            $this->setAlias('me', 'fb.do?method=users.getCurrentUser&sig=' . $sig . '&application_key=' . $this->getKey());
        }

        $token = new Token();
        $token->setTokenKey($access_token);
        $token->setName($this->getName());
        $token->setStatus(Token::STATUS_ACCESS);
        $token->setOAuthVersion($this->getVersion());

        unset($params['access_token']);

        if (count($params) > 0) {
            $token->setParams($params);
        }

        $this->setExpire($token);

        $this->setToken($token);

        // get identifier maybe need the access token
        $token->setIdentifier($this->getIdentifier());

        $this->setToken($token);

        return $token;
    }

    public function requestAuth($parameters = array())
    {
        $parameters ['response_type'] = 'code';

        return parent::requestAuth($parameters);
    }
}
