<?php

namespace VGMdb\Component\User\Security;

use Symfony\Component\HttpFoundation\RequestMatcherInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * LoginListenerRegistry allows configuration of multiple handlers for login events.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
class LoginListenerRegistry
{
    private $map = array();

    public function add(RequestMatcherInterface $requestMatcher = null, array $listeners = array())
    {
        $this->map[] = array($requestMatcher, $listeners);
    }

    public function getListeners(Request $request)
    {
        foreach ($this->map as $elements) {
            if (null === $elements[0] || $elements[0]->matches($request)) {
                return array($elements[1], $elements[2]);
            }
        }

        return array(array(), null);
    }
}
