/**
 * Copyright 2012 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package securesocial.core

import play.api.mvc._
import providers.utils.RoutesHelper
import play.api.i18n.Messages
import play.api.Logger
import play.api.libs.json.Json
import play.api.libs.oauth.ServiceInfo
import play.api.Play
import play.api.Play.current
import org.joda.time.DateTime


/**
 * A request that adds the User for the current call
 */
case class SecuredRequest[A](userId: UserId, request: Request[A]) extends WrappedRequest(request) {
  lazy val user: Identity = UserService.find(userId).get
}

/**
 * A request that adds the User for the current call
 */
case class RequestWithUser[A](userId: Option[UserId], request: Request[A]) extends WrappedRequest(request) {
  lazy val user: Option[Identity] = for {
    id <- userId;
    user <- UserService.find(id)
  } yield {
    user
  }
}


/**
 * Provides the actions that can be used to protect controllers and retrieve the current user
 * if available.
 *
 * object MyController extends SecureSocial {
 *    def protectedAction = SecuredAction { implicit request =>
 *      Ok("Hello %s".format(request.user.displayName))
 *    }
 */
trait SecureSocial extends Controller {
  /**
   * A Forbidden response for ajax clients
   * @param request
   * @tparam A
   * @return
   */
  private def ajaxCallNotAuthenticated[A](implicit request: Request[A]): PlainResult = {
    Unauthorized(Json.toJson(Map("error"->"Credentials required"))).as(JSON)
  }

  private def ajaxCallNotAuthorized[A](implicit request: Request[A]): PlainResult = {
    Forbidden( Json.toJson(Map("error" -> "Not authorized"))).as(JSON)
  }

  /**
   * A secured action.  If there is no user in the session the request is redirected
   * to the login page
   *
   * @param ajaxCall a boolean indicating whether this is an ajax call or not
   * @param authorize an Authorize object that checks if the user is authorized to invoke the action
   * @param p the body parser to use
   * @param f the wrapped action to invoke
   * @tparam A
   * @return
   */
  def SecuredAction[A](ajaxCall: Boolean, authorize: Option[Authorization], p: BodyParser[A])
                      (f: SecuredRequest[A] => Result)
                       = Action(p) {
    implicit request => {

      val result = for (
        userId <- SecureSocial.userIdFromRequest
      ) yield {
        if ( authorize.isEmpty || authorize.get.isAuthorized(userId)) {
          f(SecuredRequest(userId, request)) match {
            case plainResult: PlainResult => {
              touchSession(request.session, plainResult)
            }
            case r => r
          }
        } else {
          if ( ajaxCall ) {
            ajaxCallNotAuthorized(request)
          } else {
            Redirect(RoutesHelper.notAuthorized.absoluteURL(IdentityProvider.sslEnabled))
          }
        }
      }

      result.getOrElse({
        if ( Logger.isDebugEnabled ) {
          Logger.debug("[securesocial] anonymous user trying to access : '%s'".format(request.uri))
        }
        val response = if ( ajaxCall ) {
          ajaxCallNotAuthenticated(request)
        } else {
          Redirect(RoutesHelper.login()).flashing("error" -> Messages("securesocial.loginRequired")).withSession(
            session + (SecureSocial.OriginalUrlKey -> request.uri)
              - SecureSocial.UserKey
              - SecureSocial.ProviderKey
              - SecureSocial.LastAccessKey
          )
        }
        response.discardingCookies(Authenticator.discardingCookie)
      })
    }
  }

  /**
   * A secured action.  If there is no user in the session the request is redirected
   * to the login page.
   *
   * @param ajaxCall a boolean indicating whether this is an ajax call or not
   * @param authorize an Authorize object that checks if the user is authorized to invoke the action
   * @param f the wrapped action to invoke
   * @return
   */
  def SecuredAction(ajaxCall: Boolean, authorize: Authorization)
                   (f: SecuredRequest[AnyContent] => Result): Action[AnyContent] =
    SecuredAction(ajaxCall, Some(authorize), p = parse.anyContent)(f)

  /**
   * A secured action.  If there is no user in the session the request is redirected
   * to the login page.
   *
   * @param authorize an Authorize object that checks if the user is authorized to invoke the action
   * @param f the wrapped action to invoke
   * @return
   */
  def SecuredAction(authorize: Authorization)
                   (f: SecuredRequest[AnyContent] => Result): Action[AnyContent] =
    SecuredAction(false,authorize)(f)

  /**
   * A secured action.  If there is no user in the session the request is redirected
   * to the login page.
   *
   * @param ajaxCall a boolean indicating whether this is an ajax call or not
   * @param f the wrapped action to invoke
   * @return
   */
  def SecuredAction(ajaxCall: Boolean)
                   (f: SecuredRequest[AnyContent] => Result): Action[AnyContent] =
    SecuredAction(ajaxCall, None, parse.anyContent)(f)

  /**
   * A secured action.  If there is no user in the session the request is redirected
   * to the login page.
   *
   * @param f the wrapped action to invoke
   * @return
   */
  def SecuredAction(f: SecuredRequest[AnyContent] => Result): Action[AnyContent] =
    SecuredAction(false)(f)

  /**
   * An action that adds the current user in the request if it's available
   *
   * @param p
   * @param f
   * @tparam A
   * @return
   */
  def UserAwareAction[A](p: BodyParser[A])(f: RequestWithUser[A] => Result) = Action(p) {
    implicit request => {
      val userId = SecureSocial.userIdFromRequest
      f(RequestWithUser(userId, request)) match {
        case plainResult: PlainResult if userId.isDefined => {
          touchSession(request.session, plainResult)
        }
        case r => r
      }
    }
  }

  /**
   * An action that adds the current user in the request if it's available
   * @param f
   * @return
   */
  def UserAwareAction(f: RequestWithUser[AnyContent] => Result): Action[AnyContent] = {
    UserAwareAction(parse.anyContent)(f)
  }

  private def touchSession(requestSession: Session, result: PlainResult): Result = {
    // I can't change the session of a result directly, so I'm getting the cookie
    // and decoding it from there.
    // If there is no session in the result, then it's safe to use the
    // values from the request.
    val s = for (
      setCookie <- result.header.headers.get(SET_COOKIE) ;
      cookie <- Cookies.decode(setCookie).find(_.name == Session.COOKIE_NAME )
    ) yield {
      Session.decodeFromCookie(Some(cookie))
    }
    result.withSession(s.getOrElse(requestSession) + SecureSocial.lastAccess)
  }

}

object SecureSocial {
  // Cookie keys
  val UserKey = "user"
  val ProviderKey = "provider"
  val OriginalUrlKey = "original-url"
  val LastAccessKey = "last-access"

  val IdleTimeoutKey = "securesocial.cookie.idleTimeoutInMinutes"
  val DefaultIdleTimeout = 10
  lazy val idleTimeout = Play.application.configuration.getInt(IdleTimeoutKey).getOrElse(DefaultIdleTimeout)

  def lastAccess = (SecureSocial.LastAccessKey -> DateTime.now().toString())


  /**
   * Build a UserId object from the session data
   */
  def userIdFromRequest(implicit request: RequestHeader): Option[UserId] = {
    userFromSession match {
      case Some(userId) =>
        // Session cookie found
        Some(userId)
      case None =>
        // Check authenticator cookie
        for {
          authenticator <- authenticatorFromRequest // STATEFUL (but rare)
        } yield {
          authenticator.userId
        }
    }
  }

  /**
   * Get the Authenticator cookie from a request and check its validity
   * STATEFUL
   *
   * @param request
   * @tparam A
   * @return
   */
  private def authenticatorFromRequest(implicit request: RequestHeader): Option[Authenticator] = {
    request.cookies.get(Authenticator.cookieName) match {
      case Some(cookie) =>
        Authenticator.find(cookie.value).fold(e => None, a => a) match {
          case Some(authenticator) => 
            if ( !authenticator.isValid ) {
              Authenticator.delete(authenticator.id)
              None
            } else {
              Some(authenticator)
            }
          case None =>
            // TODO: Invalid cookie, delete from session
            None
        }
      case None => None
    }
  }

  /**
   * Build a UserId object from the session data
   *
   * @param request
   * @tparam A
   * @return
   */
  private def userFromSession[A](implicit request: RequestHeader): Option[UserId] = {
    for (
      userId <- request.session.get(SecureSocial.UserKey);
      providerId <- request.session.get(SecureSocial.ProviderKey);
      lastAccess <- lastAccessFromSession(request.session) if !isSessionExpired(lastAccess)
    ) yield {
      UserId(userId, providerId)
    }
  }

  private def lastAccessFromSession(session: Session): Option[DateTime] = {
    session.data.get(SecureSocial.LastAccessKey).map {
      DateTime.parse(_)
    }
  }

  private def isSessionExpired(lastAccess: DateTime): Boolean = {
    DateTime.now().isAfter( lastAccess.plusMinutes(idleTimeout))
  }

  /**
   * Returns the ServiceInfo needed to sign OAuth1 requests.
   *
   * @param user the user for which the serviceInfo is needed
   * @return an optional service info
   */
  def serviceInfoFor(user: Identity): Option[ServiceInfo] = {
    Registry.providers.get(user.id.providerId) match {
      case Some(p: OAuth1Provider) if p.authMethod == AuthenticationMethod.OAuth1 => Some(p.serviceInfo)
      case _ => None
    }
  }
  
  /**
   * Revokes the authenticator and session cookies
   */
  def revokeAuth[A](result: Result)(implicit request: RequestHeader): Result = {
    // Delete from play session
    val withSession = for {
      userId <- userIdFromRequest;
      user <- UserService.find(userId); // STATEFUL
      sessionFromListener <- Events.fire(new LogoutEvent(user))
    } yield {
      sessionFromListener
    }
    val newSession = withSession.getOrElse(request.session) - UserKey - ProviderKey - LastAccessKey

    // Revoke authenticator cookie
    for {
      authenticator <- authenticatorFromRequest
    } {
      Authenticator.delete(authenticator.id)
    }

    // Return stripped result
    result.withSession(newSession).discardingCookies(Authenticator.discardingCookie)
  }
}
