<?php

namespace VGMdb\Component\User;

use VGMdb\Component\Silex\AbstractResourceProvider;
use VGMdb\Component\User\Form\Type\RegistrationFormType;
use VGMdb\Component\User\Form\Flow\RegistrationFormFlow;
use VGMdb\Component\User\Form\Type\ResetPasswordFormType;
use VGMdb\Component\User\Form\Handler\RegistrationFormHandler;
use VGMdb\Component\User\Form\Handler\ResetPasswordFormHandler;
use VGMdb\Component\User\Model\Doctrine\UserManager;
use VGMdb\Component\User\Provider\UserProvider;
use VGMdb\Component\User\Security\LoginManager;
use VGMdb\Component\User\Security\LoginListenerRegistry;
use VGMdb\Component\User\Security\InteractiveLoginListener;
use VGMdb\Component\User\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use VGMdb\Component\User\Util\Canonicalizer;
use VGMdb\Component\User\Util\EmailCanonicalizer;
use VGMdb\Component\User\Util\TokenGenerator;
use VGMdb\Component\User\Util\UserManipulator;
use VGMdb\Component\User\Mailer\MustacheSwiftMailer;
use Silex\Application;
use Silex\ServiceProviderInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Encoder\BCryptPasswordEncoder;
use Symfony\Component\Security\Core\Encoder\Pbkdf2PasswordEncoder;

/**
 * Provides user management. Adapted from FriendsOfSymfony UserBundle.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
class UserServiceProvider extends AbstractResourceProvider implements ServiceProviderInterface
{
    protected $config = 'user.yml';

    public function register(Application $app)
    {
        $app['user_manager'] = $app->share(function ($app) {
            return new UserManager(
                $app['security.encoder_factory'],
                $app['user.util.username_canonicalizer'],
                $app['user.util.email_canonicalizer'],
                $app['entity_manager'],
                $app['user.model.user_class'],
                $app['user.model.auth_class']
            );
        });

        $app['user_manipulator'] = $app->share(function ($app) {
            return new UserManipulator($app['user_manager']);
        });

        $app['security.encoder_factory'] = $app->share(function ($app) {
            return new EncoderFactory(array(
                'Symfony\\Component\\Security\\Core\\User\\UserInterface' => $app['security.encoder'],
                'VGMdb\\Component\\User\\Model\\UserInterface' => $app['security.encoder']
            ));
        });

        $app['security.encoder'] = $app->share(function ($app) {
            if (isset($app['security.secure_random'])) {
                return new BCryptPasswordEncoder($app['security.secure_random'], $app['user.security.bcrypt.work_factor']);
            }

            return new Pbkdf2PasswordEncoder();
        });

        $app['user.util.username_canonicalizer'] = $app->share(function ($app) {
            return new Canonicalizer();
        });

        $app['user.util.email_canonicalizer'] = $app->share(function ($app) {
            return new EmailCanonicalizer();
        });

        $app['user.token_generator'] = $app->share(function ($app) {
            return new TokenGenerator();
        });

        $app['user_provider'] = $app->share(function ($app) {
            return new UserProvider($app['user_manager']);
        });

        $app['user.security.interactive_login_listener'] = $app->share(function ($app) {
            return new InteractiveLoginListener($app['user.security.login_listener_registry']);
        });

        $app['user.security.login_listener_registry'] = $app->share(function ($app) {
            return new LoginListenerRegistry();
        });

        $app['user.security.login_manager'] = $app->share(function ($app) {
            return new LoginManager(
                $app['security'],
                $app['security.user_checker'],
                $app['security.session_strategy'],
                $app
            );
        });

        $app['user.registration.form'] = $app->share(function ($app) {
            $form = $app['form.factory']->create($app['user.registration.form_type']);

            return $form;
        });

        $app['user.registration.form_type'] = $app->share(function ($app) {
            return new RegistrationFormType($app['user.model.user_class']);
        });

        $app['user.registration.form_flow'] = $app->share(function ($app) {
            $flow = new RegistrationFormFlow();
            $flow->setFormType($app['user.registration.form_type']);
            $flow->setFormFactory($app['form.factory']);
            $flow->setRequest($app['request']);
            $flow->setStorage($app['form.flow.storage']);
            $flow->setEventDispatcher($app['dispatcher']);

            return $flow;
        });

        $app['user.registration.form_handler'] = $app->share(function ($app) {
            return new RegistrationFormHandler(
                $app['user.registration.form_flow'],
                $app['request'],
                $app['user_manager'],
                $app['user.mailer'],
                $app['user.token_generator']
            );
        });

        $app['user.resetpassword.form'] = $app->share(function ($app) {
            $form = $app['form.factory']->create(new ResetPasswordFormType($app['user.model.user_class']));
            return $form;
        });

        $app['user.resetpassword.form_handler'] = $app->share(function ($app) {
            return new ResetPasswordFormHandler(
                $app['user.resetpassword.form'],
                $app['request'],
                $app['user_manager'],
                $app['user.mailer']
            );
        });

        $app['user.mailer'] = $app->share(function ($app) {
            return new MustacheSwiftMailer(
                $app['mailer'],
                $app['router'],
                $app['mustache'],
                $app['logger'],
                $app['user.mailer.config']
            );
        });
    }

    public function boot(Application $app)
    {
        $app['dispatcher']->addSubscriber($app['user.security.interactive_login_listener']);
    }
}
