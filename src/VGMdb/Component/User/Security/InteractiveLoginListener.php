<?php

namespace VGMdb\Component\User\Security;

use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Invokes registered handlers upon user authentication.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
class InteractiveLoginListener implements EventSubscriberInterface
{
    protected $registry;

    public function __construct(LoginListenerRegistry $registry)
    {
        $this->registry = $registry;
    }

    public function onSecurityInteractiveLogin(InteractiveLoginEvent $event)
    {
        $listeners = $this->registry->getListeners($event->getRequest());

        foreach ($listeners as $listener) {
            if ($event->isPropagationStopped()) {
                break;
            }

            $listener->handle($event);
        }
    }

    public static function getSubscribedEvents()
    {
        return array(SecurityEvents::INTERACTIVE_LOGIN => array('onSecurityInteractiveLogin', 8));
    }
}
