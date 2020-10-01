/*
 * Copyright (c) 2002-2014, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.mylutece.modules.database.authentication.web;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;

import fr.paris.lutece.plugins.mylutece.business.attribute.AttributeField;
import fr.paris.lutece.plugins.mylutece.business.attribute.AttributeFieldHome;
import fr.paris.lutece.plugins.mylutece.business.attribute.AttributeHome;
import fr.paris.lutece.plugins.mylutece.business.attribute.IAttribute;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseUser;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseUserFactory;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseUserHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.key.DatabaseUserKey;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.DatabasePlugin;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.DatabaseService;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.key.DatabaseUserKeyService;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.parameter.DatabaseUserParameterService;
import fr.paris.lutece.plugins.mylutece.service.MyLutecePlugin;
import fr.paris.lutece.plugins.mylutece.service.attribute.MyLuteceUserFieldService;
import fr.paris.lutece.plugins.mylutece.util.SecurityUtils;
import fr.paris.lutece.portal.service.captcha.CaptchaSecurityService;
import fr.paris.lutece.portal.service.i18n.I18nService;
import fr.paris.lutece.portal.service.mail.MailService;
import fr.paris.lutece.portal.service.message.SiteMessage;
import fr.paris.lutece.portal.service.message.SiteMessageException;
import fr.paris.lutece.portal.service.message.SiteMessageService;
import fr.paris.lutece.portal.service.plugin.Plugin;
import fr.paris.lutece.portal.service.plugin.PluginService;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.security.UserNotSignedException;
import fr.paris.lutece.portal.service.template.AppTemplateService;
import fr.paris.lutece.portal.service.template.DatabaseTemplateService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.portal.service.util.CryptoService;
import fr.paris.lutece.portal.web.LocalVariables;
import fr.paris.lutece.portal.web.constants.Messages;
import fr.paris.lutece.portal.web.xpages.XPage;
import fr.paris.lutece.portal.web.xpages.XPageApplication;
import fr.paris.lutece.util.ReferenceItem;
import fr.paris.lutece.util.date.DateUtil;
import fr.paris.lutece.util.html.HtmlTemplate;
import fr.paris.lutece.util.password.IPassword;
import fr.paris.lutece.util.string.StringUtil;
import fr.paris.lutece.util.url.UrlItem;


/**
 * This class provides the XPageApp that manage personalization features for
 * Mylutece Database module : login, account management, ...
 */
public class MyLuteceDatabaseApp implements XPageApplication
{
    /** serial id */
    private static final long serialVersionUID = -467672310904504414L;

    // Markers
    private static final String MARK_USER = "user";
    private static final String MARK_ROLES = "roles";
    private static final String MARK_GROUPS = "groups";
    private static final String MARK_PLUGIN_NAME = "plugin_name";
    private static final String MARK_ERROR_CODE = "error_code";
    private static final String MARK_ACTION_SUCCESSFUL = "action_successful";
    private static final String MARK_EMAIL = "email";
    private static final String MARK_ACTION_VALIDATION_EMAIL = "action_validation_email";
    private static final String MARK_ACTION_VALIDATION_SUCCESS = "action_validation_success";
    private static final String MARK_VALIDATION_URL = "validation_url";
    private static final String MARK_JCAPTCHA = "jcaptcha";
    private static final String MARK_SHOW_INPUT_LOGIN = "show_input_login";
    private static final String MARK_SHOW_INPUT_EMAIL = "show_input_email";
    private static final String MARK_REINIT_URL = "reinit_url";
    private static final String MARK_KEY = "key";
    private static final String MARK_ATTRIBUTES_LIST = "attributes_list";
    private static final String MARK_PASSWORD_MINIMUM_LENGTH = "password_minimum_length";
    private static final String MARK_PASSWORD_FORMAT_MESSAGE = "password_format_message";
    private static final String MARK_USER_ID = "user_id";
    private static final String MARK_REF = "ref";
    private static final String MARK_SITE_LINK = "site_link";
    private static final String MARK_LOGIN = "login";
    private static final String MARK_LOGIN_URL = "login_url";
    private static final String MARK_PASSWORD_HISTORY_SIZE = "password_history_size";

    // Parameters
    private static final String PARAMETER_ACTION = "action";
    private static final String PARAMETER_OLD_PASSWORD = "old_password";
    private static final String PARAMETER_NEW_PASSWORD = "new_password";
    private static final String PARAMETER_CONFIRMATION_PASSWORD = "confirmation_password";
    private static final String PARAMETER_PLUGIN_NAME = "plugin_name";
    private static final String PARAMETER_ERROR_CODE = "error_code";
    private static final String PARAMETER_EMAIL = "email";
    private static final String PARAMETER_ACTION_SUCCESSFUL = "action_successful";
    private static final String PARAMETER_LOGIN = "login";
    private static final String PARAMETER_PASSWORD = "password";
    private static final String PARAMETER_LAST_NAME = "last_name";
    private static final String PARAMETER_FIRST_NAME = "first_name";
    private static final String PARAMETER_KEY = "key";
    private static final String PARAMETER_ACTION_VALIDATION_EMAIL = "action_validation_email";
    private static final String PARAMETER_ACTION_VALIDATION_SUCCESS = "action_validation_success";
    private static final String PARAMETER_FORCE_CHANGE_PASSWORD_REINIT = "force_change_password_reinit";
    private static final String PARAMETER_TIME_BEFORE_ALERT_ACCOUNT = "time_before_alert_account";
    private static final String PARAMETER_MAIL_LOST_PASSWORD_SENDER = "mail_lost_password_sender";
    private static final String PARAMETER_MAIL_LOST_PASSWORD_SUBJECT = "mail_lost_password_subject";

    // Actions
    private static final String ACTION_CHANGE_PASSWORD = "changePassword";
    private static final String ACTION_DELETE = "delete";
    private static final String ACTION_CONFIRM_DELETE = "deleteConfirm";
    private static final String ACTION_VIEW_ACCOUNT = "viewAccount";
    private static final String ACTION_MODIFY_ACCOUNT = "modifyAccount";
    private static final String ACTION_LOST_PASSWORD = "lostPassword";
    private static final String ACTION_LOST_LOGIN = "lostLogin";
    private static final String ACTION_ACCESS_DENIED = "accessDenied";
    private static final String ACTION_CREATE_ACCOUNT = "createAccount";
    private static final String ACTION_REINIT_PASSWORD = "reinitPassword";
    private static final String ACTION_REACTIVATE_ACCOUNT = "reactivateAccount";
    private static final String ACTION_GET_RESET_PASSWORD = "getResetPasswordPage";

    // Errors
    private static final String ERROR_OLD_PASSWORD = "error_old_password";
    private static final String ERROR_CONFIRMATION_PASSWORD = "error_confirmation_password";
    private static final String ERROR_SAME_PASSWORD = "error_same_password";
    private static final String ERROR_SYNTAX_EMAIL = "error_syntax_email";
    private static final String ERROR_SENDING_EMAIL = "error_sending_email";
    private static final String ERROR_UNKNOWN_EMAIL = "error_unknown_email";
    private static final String ERROR_MANDATORY_FIELDS = "error_mandatory_fields";
    private static final String ERROR_LOGIN_ALREADY_EXISTS = "error_login_already_exists";
    private static final String ERROR_CAPTCHA = "error_captcha";
    private static final String ERROR_PASSWORD_MINIMUM_LENGTH = "password_minimum_length";
    private static final String ERROR_PASSWORD_ALREADY_USED = "password_already_used";

    // Templates
    private static final String TEMPLATE_LOST_PASSWORD_PAGE = "skin/plugins/mylutece/modules/database/lost_password.html";
    private static final String TEMPLATE_LOST_LOGIN_PAGE = "skin/plugins/mylutece/modules/database/lost_login.html";
    private static final String TEMPLATE_VIEW_ACCOUNT_PAGE = "skin/plugins/mylutece/modules/database/view_account.html";
    private static final String TEMPLATE_MODIFY_ACCOUNT_PAGE = "skin/plugins/mylutece/modules/database/modify_account.html";
    private static final String TEMPLATE_CHANGE_PASSWORD_PAGE = "skin/plugins/mylutece/modules/database/change_password.html";
    private static final String TEMPLATE_CREATE_ACCOUNT_PAGE = "skin/plugins/mylutece/modules/database/create_account.html";
    private static final String TEMPLATE_EMAIL_VALIDATION = "skin/plugins/mylutece/modules/database/email_validation.html";
    private static final String TEMPLATE_REINIT_PASSWORD_PAGE = "skin/plugins/mylutece/modules/database/reinit_password.html";
    private static final String TEMPLATE_EMAIL_LOST_LOGIN = "skin/plugins/mylutece/email_lost_login.html";

    // Properties
    private static final String PROPERTY_MYLUTECE_CHANGE_PASSWORD_URL = "mylutece-database.url.changePassword.page";
    private static final String PROPERTY_MYLUTECE_VIEW_ACCOUNT_URL = "mylutece-database.url.viewAccount.page";
    private static final String PROPERTY_MYLUTECE_CREATE_ACCOUNT_URL = "mylutece-database.url.createAccount.page";
    private static final String PROPERTY_MYLUTECE_MODIFY_ACCOUNT_URL = "mylutece-database.url.modifyAccount.page";
    private static final String PROPERTY_MYLUTECE_LOST_PASSWORD_URL = "mylutece-database.url.lostPassword.page";
    private static final String PROPERTY_MYLUTECE_LOST_LOGIN_URL = "mylutece-database.url.lostLogin.page";
    private static final String PROPERTY_MYLUTECE_RESET_PASSWORD_URL = "mylutece-database.url.resetPassword.page";
    private static final String PROPERTY_MYLUTECE_ACCESS_DENIED_URL = "mylutece-database.url.accessDenied.page";
    private static final String PROPERTY_MYLUTECE_DEFAULT_REDIRECT_URL = "mylutece-database.url.default.redirect";
    private static final String PROPERTY_MYLUTECE_DELETE_URL = "mylutece-database.url.delete.page";
    private static final String PROPERTY_MYLUTECE_TEMPLATE_ACCESS_DENIED = "mylutece-database.template.accessDenied";
    private static final String PROPERTY_MYLUTECE_TEMPLATE_ACCESS_CONTROLED = "mylutece-database.template.accessControled";
    private static final String PROPERTY_MYLUTECE_LOGIN_PAGE_URL = "mylutece.url.login.page";
    private static final String PROPERTY_MYLUTECE_REINIT_PASSWORD_URL = "mylutece-database.url.reinitPassword.page";
    private static final String PROPERTY_PORTAL_NAME = "lutece.name";
    private static final String PROPERTY_NOREPLY_EMAIL = "mail.noreply.email";
    private static final String PROPERTY_MAIL_HOST = "mail.server";
    private static final String PROPERTY_ACCOUNT_REF_ENCRYPT_ALGO = "mylutece-database.account_life_time.refEncryptionAlgorythm";
    private static final String PROPERTY_DATABASE_MAIL_LOST_PASSWORD = "mylutece_database_mailLostPassword";

    // i18n Properties
    private static final String PROPERTY_CHANGE_PASSWORD_LABEL = "module.mylutece.database.xpage.changePassword.label";
    private static final String PROPERTY_CHANGE_PASSWORD_TITLE = "module.mylutece.database.xpage.changePassword.title";
    private static final String PROPERTY_VIEW_ACCOUNT_LABEL = "module.mylutece.database.xpage.viewAccount.label";
    private static final String PROPERTY_VIEW_ACCOUNT_TITLE = "module.mylutece.database.xpage.viewAccount.title";
    private static final String PROPERTY_MODIFY_ACCOUNT_LABEL = "module.mylutece.database.xpage.modifyAccount.label";
    private static final String PROPERTY_MODIFY_ACCOUNT_TITLE = "module.mylutece.database.xpage.modifyAccount.title";
    
    private static final String PROPERTY_LOST_PASSWORD_LABEL = "module.mylutece.database.xpage.lostPassword.label";
    private static final String PROPERTY_LOST_PASSWORD_TITLE = "module.mylutece.database.xpage.lostPassword.title";
    private static final String PROPERTY_LOST_LOGIN_LABEL = "module.mylutece.database.xpage.lostLogin.label";
    private static final String PROPERTY_LOST_LOGIN_TITLE = "module.mylutece.database.xpage.lostLogin.title";
    private static final String PROPERTY_CREATE_ACCOUNT_LABEL = "module.mylutece.database.xpage.createAccount.label";
    private static final String PROPERTY_CREATE_ACCOUNT_TITLE = "module.mylutece.database.xpage.createAccount.title";
    private static final String PROPERTY_EMAIL_OBJECT = "module.mylutece.database.email.object";
    private static final String PROPERTY_EMAIL_OBJECT_LOST_LOGIN = "module.mylutece.database.email_lost_login.object";
    private static final String PROPERTY_EMAIL_VALIDATION_OBJECT = "module.mylutece.database.email_validation.object";
    private static final String PROPERTY_ACCESS_DENIED_ERROR_MESSAGE = "module.mylutece.database.siteMessage.access_denied.errorMessage";
    private static final String PROPERTY_ACCESS_DENIED_TITLE_MESSAGE = "module.mylutece.database.siteMessage.access_denied.title";
    private static final String PROPERTY_REINIT_PASSWORD_LABEL = "module.mylutece.database.xpage.reinitPassword.label";
    private static final String PROPERTY_REINIT_PASSWORD_TITLE = "module.mylutece.database.xpage.reinitPassword.title";
    private static final String PROPERTY_NO_USER_SELECTED = "mylutece.message.noUserSelected";
    private static final String PROPERTY_VALIDATE_DELETE = "mylutece.message.deleteValidate";
    private static final String PROPERTY_MESSAGE_LABEL_ERROR = "mylutece.message.labelError";
    private static final String PROPERTY_MESSAGE_LABEL_WARNING = "mylutece.message.labelWarning";
    private static final String PROPERTY_ERROR_NO_ACCOUNT_TO_REACTIVATE = "mylutece.message.error.noAccountToReactivate";
    private static final String PROPERTY_ACCOUNT_REACTIVATED = "mylutece.user.messageAccountReactivated";
    private static final String PROPERTY_ACCOUNT_REACTIVATED_TITLE = "mylutece.user.messageAccountReactivatedTitle";

    // Messages
    private static final String MESSAGE_REINIT_PASSWORD_SUCCESS = "module.mylutece.database.message.reinit_password.success";
    private static final String MESSAGE_MINIMUM_PASSWORD_LENGTH = "mylutece.message.password.minimumPasswordLength";
    private static final String MESSAGE_PASSWORD_EXPIRED = "module.mylutece.database.message.passwordExpired";
    private static final String MESSAGE_MUST_CHANGE_PASSWORD = "module.mylutece.database.message.userMustChangePassword";

    // JSP URL
    private static final String JSP_URL_GET_RESET_PASSWORD_PAGE = "jsp/site/Portal.jsp?page=mylutecedatabase&action=getResetPasswordPage";
    private static final String JSP_URL_MYLUTECE_LOGIN = "jsp/site/Portal.jsp?page=mylutece&action=login";
    private static final String JSP_URL_HOME = "Portal.jsp";

    // private fields
    private Plugin _plugin;
    private Locale _locale;
    private DatabaseUserParameterService _userParamService = DatabaseUserParameterService.getService( );
    private DatabaseUserKeyService _userKeyService = DatabaseUserKeyService.getService( );
    private CaptchaSecurityService _captchaService = new CaptchaSecurityService( );
    private DatabaseUserFactory _userFactory = DatabaseUserFactory.getFactory( );
    private DatabaseService _databaseService = DatabaseService.getService( );

    /**
     * 
     * @param request The HTTP request
     * @param plugin The plugin
     */
    public void init( HttpServletRequest request, Plugin plugin )
    {
        _locale = request.getLocale( );
        _plugin = plugin;
    }

    /**
     * 
     * @param request The HTTP request
     * @param nMode The mode (admin, ...)
     * @param plugin The plugin
     * @return The Xpage
     * @throws UserNotSignedException if user not signed
     * @throws SiteMessageException Occurs when a site message need to be
     *             displayed
     */
    public XPage getPage( HttpServletRequest request, int nMode, Plugin plugin ) throws UserNotSignedException,
            SiteMessageException
    {
        XPage page = new XPage( );
        String strAction = request.getParameter( PARAMETER_ACTION );
        init( request, plugin );

        LuteceUser luteceUser = SecurityService.getInstance( ).getRegisteredUser( request );

        if ( ( luteceUser != null ) && _databaseService.mustUserChangePassword( luteceUser, plugin )
                && !ACTION_CHANGE_PASSWORD.equals( strAction ) )
        {
            getMessageResetPassword( request );
        }
        else
        {
            if ( ACTION_CHANGE_PASSWORD.equals( strAction ) )
            {
                page = getChangePasswordPage( page, request );
            }
            else if ( ACTION_VIEW_ACCOUNT.equals( strAction ) )
            {
                page = getViewAccountPage( page, request );
            }
            else if ( ACTION_LOST_PASSWORD.equals( strAction ) )
            {
                page = getLostPasswordPage( page, request );
            }
            else if ( ACTION_LOST_LOGIN.equals( strAction ) )
            {
                page = getLostLoginPage( page, request );
            }
            else if ( ACTION_CREATE_ACCOUNT.equals( strAction ) )
            {
                page = getCreateAccountPage( page, request );
            }
            else if ( ACTION_MODIFY_ACCOUNT.equals( strAction ) )
            {
                page = getModifyAccountPage( page, request );
            }
            else if ( ACTION_REINIT_PASSWORD.equals( strAction ) )
            {
                page = getReinitPasswordPage( page, request );
            }
            else if ( ACTION_REACTIVATE_ACCOUNT.equals( strAction ) )
            {
                reactivateAccount( request );
            }
            else if ( ACTION_GET_RESET_PASSWORD.equals( strAction ) )
            {
                getMessageResetPassword( request );
            }
            else if ( ACTION_DELETE.equals( strAction ) )
            {
                if ( getRemoteUser( request ) != null )
                {
                    SiteMessageService.setMessage( request, PROPERTY_VALIDATE_DELETE, null,
                            PROPERTY_MESSAGE_LABEL_WARNING,
                            AppPropertiesService.getProperty( PROPERTY_MYLUTECE_DELETE_URL ), null,
                            SiteMessage.TYPE_CONFIRMATION );
                }
                else
                {
                    strAction = null;
                }

            }
            else if ( ACTION_CONFIRM_DELETE.equals( strAction ) )
            {
                if ( getRemoteUser( request ) != null )
                {
                    deleteAccount( request );
                    try
                    {
                        LocalVariables.getResponse( ).sendRedirect( JSP_URL_HOME );
                    }
                    catch ( IOException e )
                    {
                        AppLogService.error( e );
                    }
                }
                else
                {
                    strAction = null;
                }
            }
        }

        if ( ( strAction == null ) || strAction.equals( ACTION_ACCESS_DENIED ) || ( page == null ) )
        {
            SiteMessageService.setMessage( request, PROPERTY_ACCESS_DENIED_ERROR_MESSAGE, null,
                    PROPERTY_ACCESS_DENIED_TITLE_MESSAGE, null, null, SiteMessage.TYPE_STOP );
        }

        return page;
    }

    /**
     * Returns the NewAccount URL of the Authentication Service
     * @return The URL
     */
    public static String getChangePasswordUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_CHANGE_PASSWORD_URL );
    }

    /**
     * Returns the ViewAccount URL of the Authentication Service
     * @return The URL
     */
    public static String getViewAccountUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_VIEW_ACCOUNT_URL );
    }

    /**
     * Returns the createAccount URL of the Authentication Service
     * @return The URL
     */
    public static String getNewAccountUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_CREATE_ACCOUNT_URL );
    }
    
    /**
     * Returns the modifyAccount URL of the Authentication Service
     * @return The URL
     */
    public static String getModifyAccountUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_MODIFY_ACCOUNT_URL );
    }

    /**
     * Returns the Lost Password URL of the Authentication Service
     * @return The URL
     */
    public static String getLostPasswordUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_LOST_PASSWORD_URL );
    }

    /**
     * Returns the Lost Password URL of the Authentication Service
     * @return The URL
     */
    public static String getLostLoginUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_LOST_LOGIN_URL );
    }

    /**
     * Returns the Reset Password URL of the Authentication Service
     * @return The URL
     */
    public static String getResetPasswordUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_RESET_PASSWORD_URL );
    }

    /**
     * Get the reset password Url
     * @return the reset password Url
     */
    public static String getMessageResetPasswordUrl( )
    {
        return JSP_URL_GET_RESET_PASSWORD_PAGE;
    }

    /**
     * Returns the Default redirect URL of the Authentication Service
     * @return The URL
     */
    public static String getDefaultRedirectUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_DEFAULT_REDIRECT_URL );
    }

    /**
     * Returns the NewAccount URL of the Authentication Service
     * @return The URL
     */
    public static String getAccessDeniedUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_ACCESS_DENIED_URL );
    }

    /**
     * Returns the Login page URL of the Authentication Service
     * @return The URL
     */
    public static String getLoginPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_LOGIN_PAGE_URL );
    }

    /**
     * Returns the Reinit password page URL of the Authentication Service
     * @return the URL
     */
    public static String getReinitPageUrl( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_REINIT_PASSWORD_URL );
    }

    /**
     * This method is call by the JSP named DoMyLuteceLogout.jsp
     * @param request The HTTP request
     * @return The URL to forward depending of the result of the login.
     */
    public String doLogout( HttpServletRequest request )
    {
        SecurityService.getInstance( ).logoutUser( request );

        return getDefaultRedirectUrl( );
    }
    
    
    /**
     * Build the modifyAccount page
     * @param page The XPage object to fill
     * @param request The HTTP request
     * @return The XPage object containing the page content
     */
    private XPage getModifyAccountPage( XPage page, HttpServletRequest request )throws UserNotSignedException
    {
        String strErrorCode = request.getParameter( PARAMETER_ERROR_CODE );
        String strLastName = request.getParameter( PARAMETER_LAST_NAME );
        String strFirstName = request.getParameter( PARAMETER_FIRST_NAME );
        String strEmail = request.getParameter( PARAMETER_EMAIL );
        String strSuccess = request.getParameter( PARAMETER_ACTION_SUCCESSFUL );
        String strValidationEmail = request.getParameter( PARAMETER_ACTION_VALIDATION_EMAIL );
        String strValidationSuccess = request.getParameter( PARAMETER_ACTION_VALIDATION_SUCCESS );

    	
    	Map<String, Object> model = new HashMap<String, Object>( );
        LuteceUser luteceUser = SecurityService.getInstance( ).getRegisteredUser( request );
        
        if ( luteceUser == null )
        {
            throw new UserNotSignedException(  );
        }
        
        DatabaseUser user = getRemoteUser( request );

        if ( user == null )
        {
            return null;
        }

        if (  strLastName  !=null )
        {
            user.setLastName( strLastName );
        }

        if ( strFirstName != null  )
        {
            user.setFirstName( strFirstName );
        }

        if (  strEmail != null  )
        {
            user.setEmail( strEmail );
        }

    
        model.put( MARK_PLUGIN_NAME, _plugin.getName( ) );
        model.put( MARK_ERROR_CODE, strErrorCode );
        model.put( MARK_USER, user );
        model.put( MARK_ACTION_SUCCESSFUL, strSuccess );
        model.put( MARK_ACTION_VALIDATION_EMAIL, strValidationEmail );
        model.put( MARK_ACTION_VALIDATION_SUCCESS, strValidationSuccess );
        model.put( MARK_SHOW_INPUT_EMAIL, !_userFactory.isEmailUsedAsLogin( ) );
        model.put( MARK_PASSWORD_FORMAT_MESSAGE,
                SecurityUtils.getMessageFrontPasswordFormat( _locale, _userParamService, _plugin ) );

        if ( StringUtils.equals( strErrorCode, ERROR_PASSWORD_MINIMUM_LENGTH ) )
        {
            Object[] param = { _userParamService.findByKey( MARK_PASSWORD_MINIMUM_LENGTH, _plugin ).getName( ) };
            model.put( MARK_PASSWORD_MINIMUM_LENGTH,
                    I18nService.getLocalizedString( MESSAGE_MINIMUM_PASSWORD_LENGTH, param, _locale ) );
        }

        if ( _userParamService.isJcaptchaEnable( _plugin ) )
        {
            model.put( MARK_JCAPTCHA, _captchaService.getHtmlCode( ) );
        }

        HtmlTemplate t = AppTemplateService.getTemplate( TEMPLATE_MODIFY_ACCOUNT_PAGE, _locale, model );
        page.setContent( t.getHtml( ) );
        page.setPathLabel( I18nService.getLocalizedString( PROPERTY_MODIFY_ACCOUNT_LABEL, _locale ) );
        page.setTitle( I18nService.getLocalizedString( PROPERTY_MODIFY_ACCOUNT_TITLE, _locale ) );

        return page;
       
    }
    

    /**
     * Build the ViewAccount page
     * @param page The XPage object to fill
     * @param request The HTTP request
     * @return The XPage object containing the page content
     */
    private XPage getViewAccountPage( XPage page, HttpServletRequest request )throws UserNotSignedException
    {
        Map<String, Object> model = new HashMap<String, Object>( );
        LuteceUser luteceUser = SecurityService.getInstance( ).getRegisteredUser( request );

        if ( luteceUser == null )
        {
            throw new UserNotSignedException(  );
        }
        
        DatabaseUser user = getRemoteUser( request );

        if ( user == null )
        {
            return null;
        }

       

        model.put( MARK_USER, user );
        model.put( MARK_ROLES, luteceUser.getRoles( ) );
        model.put( MARK_GROUPS, luteceUser.getGroups( ) );
        model.put( MARK_SHOW_INPUT_LOGIN, !_userFactory.isEmailUsedAsLogin( ) );

        HtmlTemplate t = AppTemplateService.getTemplate( TEMPLATE_VIEW_ACCOUNT_PAGE, _locale, model );
        page.setContent( t.getHtml( ) );
        page.setPathLabel( I18nService.getLocalizedString( PROPERTY_VIEW_ACCOUNT_LABEL, _locale ) );
        page.setTitle( I18nService.getLocalizedString( PROPERTY_VIEW_ACCOUNT_TITLE, _locale ) );

        return page;
    }

    /**
     * Build the createAccount page
     * @param page The XPage object to fill
     * @param request The HTTP request
     * @return The XPage object containing the page content
     */
    private XPage getCreateAccountPage( XPage page, HttpServletRequest request )
    {
        Map<String, Object> model = new HashMap<String, Object>( );
        DatabaseUser user = _userFactory.newDatabaseUser( );

        String strErrorCode = request.getParameter( PARAMETER_ERROR_CODE );
        String strLogin = request.getParameter( PARAMETER_LOGIN );
        String strLastName = request.getParameter( PARAMETER_LAST_NAME );
        String strFirstName = request.getParameter( PARAMETER_FIRST_NAME );
        String strEmail = request.getParameter( PARAMETER_EMAIL );
        String strSuccess = request.getParameter( PARAMETER_ACTION_SUCCESSFUL );
        String strValidationEmail = request.getParameter( PARAMETER_ACTION_VALIDATION_EMAIL );
        String strValidationSuccess = request.getParameter( PARAMETER_ACTION_VALIDATION_SUCCESS );

        if ( StringUtils.isNotBlank( strLogin ) )
        {
            user.setLogin( strLogin );
        }

        if ( StringUtils.isNotBlank( strLastName ) )
        {
            user.setLastName( strLastName );
        }

        if ( StringUtils.isNotBlank( strFirstName ) )
        {
            user.setFirstName( strFirstName );
        }

        if ( StringUtils.isNotBlank( strEmail ) )
        {
            user.setEmail( strEmail );
        }

        Plugin myLutecePlugin = PluginService.getPlugin( MyLutecePlugin.PLUGIN_NAME );

        // Specific attributes
        List<IAttribute> listAttributes = AttributeHome.findAll( _locale, myLutecePlugin );

        for ( IAttribute attribute : listAttributes )
        {
            List<AttributeField> listAttributeFields = AttributeFieldHome.selectAttributeFieldsByIdAttribute(
                    attribute.getIdAttribute( ), myLutecePlugin );
            attribute.setListAttributeFields( listAttributeFields );
        }

        model.put( MARK_ATTRIBUTES_LIST, listAttributes );
        model.put( MARK_PLUGIN_NAME, _plugin.getName( ) );
        model.put( MARK_ERROR_CODE, strErrorCode );
        model.put( MARK_USER, user );
        model.put( MARK_ACTION_SUCCESSFUL, strSuccess );
        model.put( MARK_ACTION_VALIDATION_EMAIL, strValidationEmail );
        model.put( MARK_ACTION_VALIDATION_SUCCESS, strValidationSuccess );
        model.put( MARK_SHOW_INPUT_LOGIN, !_userFactory.isEmailUsedAsLogin( ) );
        model.put( MARK_PASSWORD_FORMAT_MESSAGE,
                SecurityUtils.getMessageFrontPasswordFormat( _locale, _userParamService, _plugin ) );

        if ( StringUtils.equals( strErrorCode, ERROR_PASSWORD_MINIMUM_LENGTH ) )
        {
            Object[] param = { _userParamService.findByKey( MARK_PASSWORD_MINIMUM_LENGTH, _plugin ).getName( ) };
            model.put( MARK_PASSWORD_MINIMUM_LENGTH,
                    I18nService.getLocalizedString( MESSAGE_MINIMUM_PASSWORD_LENGTH, param, _locale ) );
        }

        if ( _userParamService.isJcaptchaEnable( _plugin ) )
        {
            model.put( MARK_JCAPTCHA, _captchaService.getHtmlCode( ) );
        }

        HtmlTemplate t = AppTemplateService.getTemplate( TEMPLATE_CREATE_ACCOUNT_PAGE, _locale, model );
        page.setContent( t.getHtml( ) );
        page.setPathLabel( I18nService.getLocalizedString( PROPERTY_CREATE_ACCOUNT_LABEL, _locale ) );
        page.setTitle( I18nService.getLocalizedString( PROPERTY_CREATE_ACCOUNT_TITLE, _locale ) );

        return page;
    }

    /**
     * This method is call by the JSP named DoCreateAccount.jsp
     * @param request The HTTP request
     * @return The URL to forward depending of the result of the change.
     */
    public String doCreateAccount( HttpServletRequest request )
    {
        Plugin plugin = PluginService.getPlugin( request.getParameter( PARAMETER_PLUGIN_NAME ) );
        init( request, plugin );

        String strError = StringUtils.EMPTY;
        String strPassword = request.getParameter( PARAMETER_PASSWORD );
        String strConfirmation = request.getParameter( PARAMETER_CONFIRMATION_PASSWORD );
        String strLastName = request.getParameter( PARAMETER_LAST_NAME );
        String strFirstName = request.getParameter( PARAMETER_FIRST_NAME );
        String strEmail = request.getParameter( PARAMETER_EMAIL );
        String strLogin = StringUtils.EMPTY;

        if ( _userFactory.isEmailUsedAsLogin( ) )
        {
            strLogin = strEmail;
        }
        else
        {
            strLogin = request.getParameter( PARAMETER_LOGIN );
        }

        if ( StringUtils.isBlank( strLogin ) || StringUtils.isBlank( strPassword )
                || StringUtils.isBlank( strConfirmation ) || StringUtils.isBlank( strFirstName )
                || StringUtils.isBlank( strEmail ) || StringUtils.isBlank( strLastName ) )
        {
            strError = ERROR_MANDATORY_FIELDS;
        }

        // Check login unique code
        if ( StringUtils.isBlank( strError )
                && !DatabaseUserHome.findDatabaseUsersListForLogin( strLogin, _plugin ).isEmpty( ) )
        {
            strError = ERROR_LOGIN_ALREADY_EXISTS;
        }

        // Check password confirmation
        if ( StringUtils.isBlank( strError ) && !checkPassword( strPassword, strConfirmation ) )
        {
            strError = ERROR_CONFIRMATION_PASSWORD;
        }

        if ( StringUtils.isBlank( strError ) )
        {
            strError = SecurityUtils.checkPasswordForFrontOffice( _userParamService, plugin, strPassword, 0 );
        }

        // Check email format
        if ( StringUtils.isBlank( strError )
                && !StringUtil.checkEmailAndDomainName( strEmail,
                        SecurityUtils.getBannedDomainNames( _userParamService, plugin ) ) )
        {
            strError = ERROR_SYNTAX_EMAIL;
        }

        // Check email attributes
        if ( StringUtils.isBlank( strError ) && !checkSendingEmailValidation( ) )
        {
            strError = ERROR_SENDING_EMAIL;
        }

        if ( StringUtils.isBlank( strError ) && _userParamService.isJcaptchaEnable( _plugin )
                && !_captchaService.validate( request ) )
        {
            strError = ERROR_CAPTCHA;
        }

        UrlItem url = new UrlItem( AppPathService.getBaseUrl( request ) + getNewAccountUrl( ) );
        url.addParameter( PARAMETER_PLUGIN_NAME, _plugin.getName( ) );
        url.addParameter( PARAMETER_LAST_NAME, strLastName );
        url.addParameter( PARAMETER_FIRST_NAME, strFirstName );
        url.addParameter( PARAMETER_EMAIL, strEmail );

        if ( !_userFactory.isEmailUsedAsLogin( ) )
        {
            url.addParameter( PARAMETER_LOGIN, strLogin );
        }

        if ( StringUtils.isBlank( strError ) )
        {
            boolean bAccountCreationValidationEmail = _userParamService.isAccountCreationValidationEmail( _plugin );
            DatabaseUser databaseUser = _userFactory.newDatabaseUser( );
            databaseUser.setLogin( strLogin );
            databaseUser.setLastName( strLastName );
            databaseUser.setFirstName( strFirstName );
            databaseUser.setEmail( strEmail );

            int nStatus = bAccountCreationValidationEmail ? DatabaseUser.STATUS_NOT_ACTIVATED
                    : DatabaseUser.STATUS_ACTIVATED;
            databaseUser.setStatus( nStatus );
            databaseUser = _databaseService.doCreateUser( databaseUser, strPassword, _plugin );

            int nUserId = DatabaseUserHome.findDatabaseUserIdFromLogin( strLogin, _plugin );

            if ( nUserId > 0 )
            {
                _databaseService.doInsertNewPasswordInHistory( strPassword, nUserId, plugin );
            }

            MyLuteceUserFieldService.doCreateUserFields( databaseUser.getUserId( ), request, _locale );

            if ( bAccountCreationValidationEmail )
            {
                DatabaseUserKey userKey = _userKeyService.create( databaseUser.getUserId( ) );

                String strName = AppPropertiesService.getProperty( PROPERTY_PORTAL_NAME );
                String strSender = AppPropertiesService.getProperty( PROPERTY_NOREPLY_EMAIL );
                String strObject = I18nService.getLocalizedString( PROPERTY_EMAIL_VALIDATION_OBJECT, _locale );

                // Send validation email
                Map<String, Object> model = new HashMap<String, Object>( );
                model.put( MARK_VALIDATION_URL, _userKeyService.getValidationUrl( userKey.getKey( ), request ) );
                model.put( MARK_SITE_LINK, MailService.getSiteLink( AppPathService.getBaseUrl( request ), true ) );

                HtmlTemplate template = AppTemplateService.getTemplate( TEMPLATE_EMAIL_VALIDATION, _locale, model );
                MailService.sendMailHtml( strEmail, strName, strSender, strObject, template.getHtml( ) );
                url.addParameter( PARAMETER_ACTION_VALIDATION_EMAIL, getDefaultRedirectUrl( ) );
            }
            else
            {
                url.addParameter( PARAMETER_ACTION_SUCCESSFUL, getDefaultRedirectUrl( ) );
            }
        }
        else
        {
            url.addParameter( PARAMETER_ERROR_CODE, strError );
        }

        return url.getUrl( );
    }
    
    
    
    /**
     * This method is call by the JSP named DoModifyAccount.jsp
     * @param request The HTTP request
     * @return The URL to forward depending of the result of the change.
     */
    public String doModifyAccount( HttpServletRequest request )throws UserNotSignedException
    {
    	DatabaseUser user = getRemoteUser( request );
    	
    	if ( user == null )
         {
             return getLoginPageUrl();
         }
    	Plugin plugin = PluginService.getPlugin( request.getParameter( PARAMETER_PLUGIN_NAME ) );
        init( request, plugin );

        String strError = StringUtils.EMPTY;
        String strLastName = request.getParameter( PARAMETER_LAST_NAME );
        String strFirstName = request.getParameter( PARAMETER_FIRST_NAME );
        String strEmail = request.getParameter( PARAMETER_EMAIL );
   
        if (  _userParamService.isJcaptchaEnable( _plugin )
                && !_captchaService.validate( request ) )
        {
            strError = ERROR_CAPTCHA;
        }
        
    

        else 
        	
        {
        
	        if ( (!_userFactory.isEmailUsedAsLogin( ) && StringUtils.isBlank( strEmail ) )|| StringUtils.isBlank( strFirstName )
	                || StringUtils.isBlank( strEmail ) || StringUtils.isBlank( strLastName ) )
	        {
	            strError = ERROR_MANDATORY_FIELDS;
	        }
	
	    
	
	        // Check email format
	        if ( StringUtils.isBlank( strError )
	                && (!_userFactory.isEmailUsedAsLogin( ) && !StringUtil.checkEmailAndDomainName( strEmail,
	                        SecurityUtils.getBannedDomainNames( _userParamService, plugin ) )) )
	        {
	            strError = ERROR_SYNTAX_EMAIL;
	        }
        
        }
          
        UrlItem url = new UrlItem( AppPathService.getBaseUrl( request ) + getModifyAccountUrl( ) );
        url.addParameter( PARAMETER_PLUGIN_NAME, _plugin.getName( ) );
        url.addParameter( PARAMETER_LAST_NAME, strLastName );
        url.addParameter( PARAMETER_FIRST_NAME, strFirstName );
        url.addParameter( PARAMETER_EMAIL, strEmail );

        if ( StringUtils.isBlank( strError ) )
        {
          
            user.setLastName( strLastName );
            user.setFirstName( strFirstName );
            user.setEmail( strEmail );
            _databaseService.doUpdateUser(user, plugin);
            //add action successFul
            url.addParameter( PARAMETER_ACTION_SUCCESSFUL, getDefaultRedirectUrl( ) );
        }
        else
        {
            url.addParameter( PARAMETER_ERROR_CODE, strError );
        }

        return url.getUrl( );
    }
    
    
    

    /**
     * Do validate an account
     * @param request the HTTP request
     * @return the login page url
     */
    public String doValidateAccount( HttpServletRequest request )
    {
        Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );
        init( request, plugin );

        UrlItem url = new UrlItem( AppPathService.getBaseUrl( request ) + getNewAccountUrl( ) );
        url.addParameter( PARAMETER_PLUGIN_NAME, _plugin.getName( ) );

        String strKey = request.getParameter( PARAMETER_KEY );

        if ( StringUtils.isNotBlank( strKey ) )
        {
            DatabaseUserKey userKey = _userKeyService.findByPrimaryKey( strKey );

            if ( userKey != null )
            {
                DatabaseUser databaseUser = DatabaseUserHome.findByPrimaryKey( userKey.getUserId( ), _plugin );

                if ( databaseUser != null )
                {
                    databaseUser.setStatus( DatabaseUser.STATUS_ACTIVATED );
                    _databaseService.doUpdateUser( databaseUser, _plugin );
                    _userKeyService.remove( strKey );
                    url.addParameter( PARAMETER_ACTION_VALIDATION_SUCCESS, getDefaultRedirectUrl( ) );

                    if ( _userParamService.isAutoLoginAfterValidationEmail( plugin ) )
                    {
                        DatabaseService.getService( ).doAutoLoginDatabaseUser( request, databaseUser, plugin );
                    }
                }
            }
        }

        return url.getUrl( );
    }

    /**
     * Get reinit password page
     * @param page the page
     * @param request the HTTP servlet request
     * @return the page
     * @throws SiteMessageException site message if the key is wrong
     */
    public XPage getReinitPasswordPage( XPage page, HttpServletRequest request ) throws SiteMessageException
    {
        String strActionSuccess = request.getParameter( PARAMETER_ACTION_SUCCESSFUL );

        if ( StringUtils.isNotBlank( strActionSuccess ) )
        {
            SiteMessageService.setMessage( request, MESSAGE_REINIT_PASSWORD_SUCCESS, SiteMessage.TYPE_INFO,
                    AppPathService.getBaseUrl( request ) + strActionSuccess );
        }

        String strKey = request.getParameter( PARAMETER_KEY );
        DatabaseUserKey key = null;

        if ( StringUtils.isNotBlank( strKey ) )
        {
            key = _userKeyService.findByPrimaryKey( strKey );
        }

        LuteceUser luteceUser = SecurityService.getInstance( ).getRegisteredUser( request );

        if ( key == null )
        {
            key = _userKeyService.findKeyByLogin( luteceUser.getName( ) );
        }

        // If the user is logged in, has no key and must change his password, we generate a new key
        if ( ( key == null ) && ( luteceUser != null ) && _databaseService.mustUserChangePassword( luteceUser, _plugin ) )
        {
            DatabaseUser user = getRemoteUser( request );
            key = _userKeyService.create( user.getUserId( ) );
        }

        if ( key != null )
        {
            strKey = key.getKey( );

            String strErrorCode = request.getParameter( PARAMETER_ERROR_CODE );
            Map<String, Object> model = new HashMap<String, Object>( );
            model.put( MARK_ERROR_CODE, strErrorCode );

            if ( StringUtils.equals( strErrorCode, ERROR_PASSWORD_MINIMUM_LENGTH ) )
            {
                Object[] param = { _userParamService.findByKey( MARK_PASSWORD_MINIMUM_LENGTH, _plugin ).getName( ) };
                model.put( MARK_PASSWORD_MINIMUM_LENGTH,
                        I18nService.getLocalizedString( MESSAGE_MINIMUM_PASSWORD_LENGTH, param, _locale ) );
            }
            model.put( MARK_PASSWORD_FORMAT_MESSAGE,
                    SecurityUtils.getMessageFrontPasswordFormat( _locale, _userParamService, _plugin ) );
            model.put( MARK_KEY, strKey );
            model.put( MARK_ACTION_SUCCESSFUL, request.getParameter( PARAMETER_ACTION_SUCCESSFUL ) );

            HtmlTemplate t = AppTemplateService.getTemplate( TEMPLATE_REINIT_PASSWORD_PAGE, _locale, model );
            page.setContent( t.getHtml( ) );
            page.setPathLabel( I18nService.getLocalizedString( PROPERTY_REINIT_PASSWORD_LABEL, _locale ) );
            page.setTitle( I18nService.getLocalizedString( PROPERTY_REINIT_PASSWORD_TITLE, _locale ) );
        }
        else
        {
            SiteMessageService.setMessage( request, Messages.USER_ACCESS_DENIED, SiteMessage.TYPE_STOP,
                    AppPathService.getBaseUrl( request ) + getDefaultRedirectUrl( ) );
        }

        return page;
    }

    /**
     * Do reinit the password
     * @param request the http servlet request
     * @return the url return
     */
    public String doReinitPassword( HttpServletRequest request )
    {
        Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );
        init( request, plugin );

        String strKey = request.getParameter( PARAMETER_KEY );

        UrlItem url = new UrlItem( AppPathService.getBaseUrl( request ) + getReinitPageUrl( ) );
        url.addParameter( PARAMETER_KEY, strKey );

        if ( StringUtils.isNotBlank( strKey ) )
        {
            DatabaseUserKey userKey = _userKeyService.findByPrimaryKey( strKey );

            if ( userKey != null )
            {
                DatabaseUser databaseUser = DatabaseUserHome.findByPrimaryKey( userKey.getUserId( ), _plugin );

                if ( databaseUser != null )
                {
                    String strPassword = request.getParameter( PARAMETER_PASSWORD );
                    String strConfirmationPassword = request.getParameter( PARAMETER_CONFIRMATION_PASSWORD );

                    if ( !( StringUtils.isNotBlank( strPassword ) && StringUtils.isNotBlank( strConfirmationPassword ) && strPassword
                            .equals( strConfirmationPassword ) ) )
                    {
                        url.addParameter( PARAMETER_ERROR_CODE, ERROR_CONFIRMATION_PASSWORD );

                        return url.getUrl( );
                    }

                    String strErrorCode = SecurityUtils.checkPasswordForFrontOffice( _userParamService, plugin,
                            strPassword, userKey.getUserId( ) );

                    if ( StringUtils.isBlank( strErrorCode ) )
                    {
                        strErrorCode = checkPasswordHistory( strPassword, userKey.getUserId( ), plugin );
                    }

                    if ( strErrorCode != null )
                    {
                        url.addParameter( PARAMETER_ERROR_CODE, strErrorCode );

                        return url.getUrl( );
                    }

                    _databaseService.doModifyPassword( databaseUser, strPassword, _plugin );
                    _databaseService.doModifyResetPassword( databaseUser, Boolean.FALSE, _plugin );
                    _databaseService.doInsertNewPasswordInHistory( strPassword, databaseUser.getUserId( ), plugin );
                    _userKeyService.remove( userKey.getKey( ) );
                    url.addParameter( PARAMETER_ACTION_SUCCESSFUL, getDefaultRedirectUrl( ) );
                }
            }
        }

        return url.getUrl( );
    }

    /**
     * Checks, if configured, if a password is not already in the password history
     * @param strPassword the password to check
     * @param nUserId the user ID
     * @param plugin the plugin
     * @return an error string, or <code>null</code>
     */
    private String checkPasswordHistory( String strPassword, int nUserId, Plugin plugin )
    {
        int nPasswordHistorySize = SecurityUtils.getIntegerSecurityParameter( _userParamService, plugin, MARK_PASSWORD_HISTORY_SIZE );

        if ( nPasswordHistorySize > 0 )
        {
            List<IPassword> passwordHistory = DatabaseUserHome.selectUserPasswordHistory( nUserId, plugin );

            if ( nPasswordHistorySize < passwordHistory.size(  ) )
            {
                passwordHistory = passwordHistory.subList( 0, nPasswordHistorySize );
            }

            boolean passwordFound = false;
            for ( IPassword password : passwordHistory )
            {
                if ( password.check( strPassword ) )
                {
                    passwordFound = true;
                    break;
                }
            }
            if ( passwordFound )
            {
                return ERROR_PASSWORD_ALREADY_USED;
            }
        }
        return null;
    }

    /**
     * Build the default Lost password page
     * @param page The XPage object to fill
     * @param request The HTTP request
     * @return The XPage object containing the page content
     */
    private XPage getLostPasswordPage( XPage page, HttpServletRequest request )
    {
        Map<String, Object> model = new HashMap<String, Object>( );
        String strErrorCode = request.getParameter( PARAMETER_ERROR_CODE );
        String strStateSending = request.getParameter( PARAMETER_ACTION_SUCCESSFUL );
        String strEmail = request.getParameter( PARAMETER_EMAIL );

        model.put( MARK_PLUGIN_NAME, _plugin.getName( ) );
        model.put( MARK_ERROR_CODE, strErrorCode );
        model.put( MARK_ACTION_SUCCESSFUL, strStateSending );
        model.put( MARK_EMAIL, strEmail );

        HtmlTemplate t = AppTemplateService.getTemplate( TEMPLATE_LOST_PASSWORD_PAGE, _locale, model );
        page.setContent( t.getHtml( ) );
        page.setPathLabel( I18nService.getLocalizedString( PROPERTY_LOST_PASSWORD_LABEL, _locale ) );
        page.setTitle( I18nService.getLocalizedString( PROPERTY_LOST_PASSWORD_TITLE, _locale ) );

        return page;
    }

    /**
     * Build the default Lost login page
     * @param page The XPage object to fill
     * @param request The HTTP request
     * @return The XPage object containing the page content
     */
    private XPage getLostLoginPage( XPage page, HttpServletRequest request )
    {
        Map<String, Object> model = new HashMap<String, Object>( );
        String strErrorCode = request.getParameter( PARAMETER_ERROR_CODE );
        String strStateSending = request.getParameter( PARAMETER_ACTION_SUCCESSFUL );
        String strEmail = request.getParameter( PARAMETER_EMAIL );

        model.put( MARK_PLUGIN_NAME, _plugin.getName( ) );
        model.put( MARK_ERROR_CODE, strErrorCode );
        model.put( MARK_ACTION_SUCCESSFUL, strStateSending );
        model.put( MARK_EMAIL, strEmail );

        HtmlTemplate t = AppTemplateService.getTemplate( TEMPLATE_LOST_LOGIN_PAGE, _locale, model );
        page.setContent( t.getHtml( ) );
        page.setPathLabel( I18nService.getLocalizedString( PROPERTY_LOST_LOGIN_LABEL, _locale ) );
        page.setTitle( I18nService.getLocalizedString( PROPERTY_LOST_LOGIN_TITLE, _locale ) );

        return page;
    }

    /**
     * Build the default Change password page
     * @param page The XPage object to fill
     * @param request The HTTP request
     * @return The XPage object containing the page content
     */
    private XPage getChangePasswordPage( XPage page, HttpServletRequest request )
    {
        Map<String, Object> model = new HashMap<String, Object>( );
        String strErrorCode = request.getParameter( PARAMETER_ERROR_CODE );
        String strSuccess = request.getParameter( PARAMETER_ACTION_SUCCESSFUL );

        model.put( MARK_PLUGIN_NAME, _plugin.getName( ) );
        model.put( MARK_ERROR_CODE, strErrorCode );
        model.put( MARK_ACTION_SUCCESSFUL, strSuccess );

        if ( StringUtils.equals( strErrorCode, ERROR_PASSWORD_MINIMUM_LENGTH ) )
        {
            Object[] param = { _userParamService.findByKey( MARK_PASSWORD_MINIMUM_LENGTH, _plugin ).getName( ) };
            model.put( MARK_PASSWORD_MINIMUM_LENGTH,
                    I18nService.getLocalizedString( MESSAGE_MINIMUM_PASSWORD_LENGTH, param, _locale ) );
        }

        HtmlTemplate t = AppTemplateService.getTemplate( TEMPLATE_CHANGE_PASSWORD_PAGE, _locale, model );
        page.setContent( t.getHtml( ) );
        page.setPathLabel( I18nService.getLocalizedString( PROPERTY_CHANGE_PASSWORD_LABEL, _locale ) );
        page.setTitle( I18nService.getLocalizedString( PROPERTY_CHANGE_PASSWORD_TITLE, _locale ) );

        return page;
    }

    /**
     * This method is call by the JSP named DoChangePassword.jsp
     * @param request The HTTP request
     * @return The URL to forward depending of the result of the change.
     */
    public String doChangePassword( HttpServletRequest request )
    {
        Plugin plugin = PluginService.getPlugin( request.getParameter( PARAMETER_PLUGIN_NAME ) );
        init( request, plugin );

        UrlItem url = new UrlItem( AppPathService.getBaseUrl( request ) + getChangePasswordUrl( ) );
        url.addParameter( PARAMETER_PLUGIN_NAME, _plugin.getName( ) );

        String strError = StringUtils.EMPTY;
        DatabaseUser user = getRemoteUser( request );
        String strOldPassword = request.getParameter( PARAMETER_OLD_PASSWORD );
        String strNewPassword = request.getParameter( PARAMETER_NEW_PASSWORD );
        String strConfirmationPassword = request.getParameter( PARAMETER_CONFIRMATION_PASSWORD );

        if ( ( user == null ) )
        {
            return AppPathService.getBaseUrl( request );
        }

        if ( StringUtils.isBlank( strOldPassword ) || StringUtils.isBlank( strNewPassword )
                || StringUtils.isBlank( strConfirmationPassword ) )
        {
            strError = ERROR_MANDATORY_FIELDS;
        }

        if ( StringUtils.isBlank( strError )
                && !_databaseService.checkPassword( user.getLogin( ), strOldPassword, _plugin ) )
        {
            strError = ERROR_OLD_PASSWORD;
        }

        if ( StringUtils.isBlank( strError ) && !checkPassword( strNewPassword, strConfirmationPassword ) )
        {
            strError = ERROR_CONFIRMATION_PASSWORD;
        }

        if ( StringUtils.isBlank( strError ) && strNewPassword.equals( strOldPassword ) )
        {
            strError = ERROR_SAME_PASSWORD;
        }

        if ( StringUtils.isBlank( strError ) )
        {
            strError = SecurityUtils.checkPasswordForFrontOffice( _userParamService, plugin, strNewPassword,
                    user.getUserId( ) );
        }

        if ( StringUtils.isBlank( strError ) )
        {
            strError = checkPasswordHistory( strNewPassword, user.getUserId( ), plugin );
        }

        if ( StringUtils.isBlank( strError ) )
        {
            _databaseService.doModifyPassword( user, strNewPassword, _plugin );
            _databaseService.doInsertNewPasswordInHistory( strNewPassword, user.getUserId( ), plugin );
            _databaseService.doModifyResetPassword( user, false, _plugin );

            url.addParameter( PARAMETER_ACTION_SUCCESSFUL, getDefaultRedirectUrl( ) );
        }
        else
        {
            url.addParameter( PARAMETER_ERROR_CODE, strError );
        }

        return url.getUrl( );
    }

    /**
     * Check the password with the password confirmation string Check if
     * password is empty
     * 
     * @param strPassword The password
     * @param strConfirmation The password confirmation
     * @return true if password is equal to confirmation password and not empty
     */
    private boolean checkPassword( String strPassword, String strConfirmation )
    {
        boolean bIsPasswordCorrect = false;

        if ( StringUtils.isNotBlank( strPassword ) && StringUtils.isNotBlank( strConfirmation )
                && strPassword.equals( strConfirmation ) )
        {
            bIsPasswordCorrect = true;
        }

        return bIsPasswordCorrect;
    }

    /**
     * This method is call by the JSP named DoSendPassword.jsp
     * @param request The HTTP request
     * @return The URL to forward depending of the result of the sending.
     */
    public String doSendPassword( HttpServletRequest request )
    {
        Plugin plugin = PluginService.getPlugin( request.getParameter( PARAMETER_PLUGIN_NAME ) );
        init( request, plugin );

        String strError = null;
        UrlItem url = null;
        Collection<DatabaseUser> listUser = null;

        String strEmail = request.getParameter( PARAMETER_EMAIL );
        url = new UrlItem( AppPathService.getBaseUrl( request ) + getLostPasswordUrl( ) );
        url.addParameter( PARAMETER_PLUGIN_NAME, _plugin.getName( ) );
        url.addParameter( PARAMETER_EMAIL, strEmail );

        // Check mandatory fields
        if ( StringUtils.isBlank( strEmail ) )
        {
            strError = ERROR_MANDATORY_FIELDS;
        }

        // Check email format
        if ( StringUtils.isBlank( strError ) && !StringUtil.checkEmail( strEmail ) )
        {
            strError = ERROR_SYNTAX_EMAIL;
        }

        listUser = DatabaseUserHome.findDatabaseUsersListForEmail( strEmail, _plugin );

        if ( StringUtils.isBlank( strError ) && ( ( listUser == null ) || ( listUser.size( ) == 0 ) ) )
        {
            strError = ERROR_UNKNOWN_EMAIL;
        }

        if ( !checkSendingPasswordEmail( ) )
        {
            strError = ERROR_SENDING_EMAIL;
        }

        if ( StringUtils.isBlank( strError ) )
        {
            for ( DatabaseUser user : listUser )
            {
                if ( user.isActive( ) )
                {
                    // make password
                    String strPassword = SecurityUtils.makePassword( _userParamService, _plugin );

                    // update password
                    String strEncryptedPassword = strPassword;

                    _databaseService.doModifyPassword( user, strEncryptedPassword, _plugin );

                    if ( SecurityUtils.getBooleanSecurityParameter( _userParamService, plugin,
                            PARAMETER_FORCE_CHANGE_PASSWORD_REINIT ) )
                    {
                        _databaseService.doModifyResetPassword( user, Boolean.TRUE, _plugin );
                    }

                    DatabaseUserHome.update( user, _plugin );

                    String strHost = AppPropertiesService.getProperty( PROPERTY_MAIL_HOST );

                    if ( StringUtils.isBlank( strError ) && StringUtils.isBlank( strHost ) )
                    {
                        strError = ERROR_SENDING_EMAIL;
                    }
                    else
                    {
                        HashMap<String, Object> model = new HashMap<String, Object>( );
                        model.put( PARAMETER_NEW_PASSWORD, strPassword );
                        model.put( MARK_SITE_LINK, MailService.getSiteLink( AppPathService.getBaseUrl( request ), true ) );

                        DatabaseUserKey key = _userKeyService.create( user.getUserId( ) );
                        model.put( MARK_REINIT_URL, _userKeyService.getReinitUrl( key.getKey( ), request ) );

                        HtmlTemplate template = AppTemplateService.getTemplateFromStringFtl(
                                DatabaseTemplateService.getTemplateFromKey( PROPERTY_DATABASE_MAIL_LOST_PASSWORD ),
                                _locale, model );

                        ReferenceItem referenceItem = _userParamService.findByKey( PARAMETER_MAIL_LOST_PASSWORD_SENDER,
                                plugin );
                        String strSender = ( referenceItem == null ) ? StringUtils.EMPTY : referenceItem.getName( );
			String strSenderEmail = AppPropertiesService.getProperty( PROPERTY_NOREPLY_EMAIL );

                        referenceItem = _userParamService.findByKey( PARAMETER_MAIL_LOST_PASSWORD_SUBJECT, plugin );

                        String strSubject = ( referenceItem == null ) ? StringUtils.EMPTY : referenceItem.getName( );

                        MailService.sendMailHtml( strEmail, strSender, strSenderEmail, strSubject, template.getHtml( ) );
                    }
                }
            }

            url.addParameter( PARAMETER_ACTION_SUCCESSFUL, getDefaultRedirectUrl( ) );
        }
        else
        {
            url.addParameter( PARAMETER_ERROR_CODE, strError );
        }

        return url.getUrl( );
    }

    /**
     * This method is call by the JSP named DoSendLogin.jsp
     * @param request The HTTP request
     * @return The URL to forward depending of the result of the sending.
     */
    public String doSendLogin( HttpServletRequest request )
    {
        Plugin plugin = PluginService.getPlugin( request.getParameter( PARAMETER_PLUGIN_NAME ) );
        init( request, plugin );

        String strError = null;
        UrlItem url = null;
        Collection<DatabaseUser> listUser = null;

        String strEmail = request.getParameter( PARAMETER_EMAIL );
        url = new UrlItem( AppPathService.getBaseUrl( request ) + getLostLoginUrl( ) );
        url.addParameter( PARAMETER_PLUGIN_NAME, _plugin.getName( ) );
        url.addParameter( PARAMETER_EMAIL, strEmail );

        // Check mandatory fields
        if ( StringUtils.isBlank( strEmail ) )
        {
            strError = ERROR_MANDATORY_FIELDS;
        }

        // Check email format
        if ( StringUtils.isBlank( strError ) && !StringUtil.checkEmail( strEmail ) )
        {
            strError = ERROR_SYNTAX_EMAIL;
        }

        listUser = DatabaseUserHome.findDatabaseUsersListForEmail( strEmail, _plugin );

        if ( StringUtils.isBlank( strError ) && ( ( listUser == null ) || ( listUser.size( ) == 0 ) ) )
        {
            strError = ERROR_UNKNOWN_EMAIL;
        }

        if ( !checkSendingEmail( PROPERTY_EMAIL_OBJECT_LOST_LOGIN ) )
        {
            strError = ERROR_SENDING_EMAIL;
        }

        if ( StringUtils.isBlank( strError ) )
        {
            for ( DatabaseUser user : listUser )
            {
                if ( user.isActive( ) )
                {
                    String strHost = AppPropertiesService.getProperty( PROPERTY_MAIL_HOST );
                    String strSender = AppPropertiesService.getProperty( PROPERTY_NOREPLY_EMAIL );
                    String strObject = I18nService.getLocalizedString( PROPERTY_EMAIL_OBJECT_LOST_LOGIN, _locale );

                    if ( StringUtils.isBlank( strError )
                            && ( StringUtils.isBlank( strHost ) || StringUtils.isBlank( strSender ) || StringUtils
                                    .isBlank( strObject ) ) )
                    {
                        strError = ERROR_SENDING_EMAIL;
                    }
                    else
                    {
                        HashMap<String, Object> model = new HashMap<String, Object>( );
                        model.put( MARK_LOGIN, user.getLogin( ) );
                        model.put( MARK_SITE_LINK, MailService.getSiteLink( AppPathService.getBaseUrl( request ), true ) );
                        model.put( MARK_LOGIN_URL, AppPathService.getBaseUrl( request ) + JSP_URL_MYLUTECE_LOGIN );

                        HtmlTemplate template = AppTemplateService.getTemplate( TEMPLATE_EMAIL_LOST_LOGIN, _locale,
                                model );
                        MailService.sendMailHtml( strEmail, strSender, strSender, strObject, template.getHtml( ) );
                    }
                }
            }

            url.addParameter( PARAMETER_ACTION_SUCCESSFUL, getDefaultRedirectUrl( ) );
        }
        else
        {
            url.addParameter( PARAMETER_ERROR_CODE, strError );
        }

        return url.getUrl( );
    }

    /**
     * Returns the template for access denied
     * @return The template path
     */
    public static String getAccessDeniedTemplate( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_TEMPLATE_ACCESS_DENIED );
    }

    /**
     * Returns the template for access controled
     * @return The template path
     */
    public static String getAccessControledTemplate( )
    {
        return AppPropertiesService.getProperty( PROPERTY_MYLUTECE_TEMPLATE_ACCESS_CONTROLED );
    }

    /**
     * Get the remote user
     * 
     * @param request The HTTP request
     * @return The Database User
     */
    private DatabaseUser getRemoteUser( HttpServletRequest request )
    {
        LuteceUser luteceUser = SecurityService.getInstance( ).getRegisteredUser( request );

        if ( luteceUser == null )
        {
            return null;
        }

        Collection<DatabaseUser> listUsers = DatabaseUserHome.findDatabaseUsersListForLogin( luteceUser.getName( ),
                _plugin );

        if ( listUsers.size( ) != 1 )
        {
            return null;
        }

        DatabaseUser user = listUsers.iterator( ).next( );

        return user;
    }

    /**
     * Check if the parameters for the email validation are correctly filled
     * @return true if they are correctly filled, false otherwise
     */
    private boolean checkSendingEmailValidation( )
    {
        boolean bIsCorrect = false;
        boolean bAccountCreationValidationEmail = _userParamService.isAccountCreationValidationEmail( _plugin );

        if ( bAccountCreationValidationEmail )
        {
            bIsCorrect = checkSendingEmail( PROPERTY_EMAIL_VALIDATION_OBJECT );
        }
        else
        {
            bIsCorrect = true;
        }

        return bIsCorrect;
    }

    /**
     * Check if the parameters for the password email are correctly filled
     * @return true if they are correctly filled, false otherwise
     */
    private boolean checkSendingPasswordEmail( )
    {
        return checkSendingEmail( PROPERTY_EMAIL_OBJECT );
    }

    /**
     * Check if the parameters for sending an email are correctly filled
     * @param strPropertyObject the property of the object of the email
     * @return true if they are correctly filled, false otherwise
     */
    private boolean checkSendingEmail( String strPropertyObject )
    {
        boolean bIsCorrect = false;
        String strName = AppPropertiesService.getProperty( PROPERTY_PORTAL_NAME );
        String strSender = AppPropertiesService.getProperty( PROPERTY_NOREPLY_EMAIL );
        String strObject = I18nService.getLocalizedString( strPropertyObject, _locale );

        if ( StringUtils.isNotBlank( strName ) && StringUtils.isNotBlank( strSender )
                && StringUtils.isNotBlank( strObject ) )
        {
            bIsCorrect = true;
        }

        return bIsCorrect;
    }

    /**
     * Reactivate an account if necessary
     * @param request The request
     * @throws SiteMessageException A SiteMessageException is ALWAYS thrown
     */
    public void reactivateAccount( HttpServletRequest request ) throws SiteMessageException
    {
        String strUserId = request.getParameter( MARK_USER_ID );
        String strRef = request.getParameter( MARK_REF );

        int nUserId = -1;

        if ( ( strUserId != null ) && StringUtils.isNotBlank( strUserId ) )
        {
            try
            {
                nUserId = Integer.parseInt( strUserId );
            }
            catch ( NumberFormatException e )
            {
                nUserId = -1;
            }
        }

        if ( ( nUserId < 0 ) || StringUtils.isEmpty( strRef ) )
        {
            SiteMessageService.setMessage( request, PROPERTY_NO_USER_SELECTED, null, PROPERTY_MESSAGE_LABEL_ERROR,
                    AppPropertiesService.getProperty( PROPERTY_MYLUTECE_DEFAULT_REDIRECT_URL ), null,
                    SiteMessage.TYPE_ERROR );
        }
        else
        {
            DatabaseUser user = DatabaseUserHome.findByPrimaryKey( nUserId, _plugin );

            if ( ( user == null )
                    || ( user.getAccountMaxValidDate( ) == null )
                    || !StringUtils.equals( CryptoService.encrypt(
                            Long.toString( user.getAccountMaxValidDate( ).getTime( ) ),
                            AppPropertiesService.getProperty( PROPERTY_ACCOUNT_REF_ENCRYPT_ALGO ) ), strRef ) )
            {
                SiteMessageService.setMessage( request, PROPERTY_NO_USER_SELECTED, null, PROPERTY_MESSAGE_LABEL_ERROR,
                        AppPropertiesService.getProperty( PROPERTY_MYLUTECE_DEFAULT_REDIRECT_URL ), null,
                        SiteMessage.TYPE_ERROR );
            }

            int nbDaysBeforeFirstAlert = SecurityUtils.getIntegerSecurityParameter( _userParamService, _plugin,
                    PARAMETER_TIME_BEFORE_ALERT_ACCOUNT );
            Timestamp firstAlertMaxDate = new Timestamp( new java.util.Date( ).getTime( )
                    + DateUtil.convertDaysInMiliseconds( nbDaysBeforeFirstAlert ) );

            // If the account is close to expire but has not expired yet
            if ( user.getAccountMaxValidDate( ) != null )
            {
                if ( ( user.getAccountMaxValidDate( ).getTime( ) < firstAlertMaxDate.getTime( ) )
                        && ( user.getStatus( ) < DatabaseUser.STATUS_EXPIRED ) )
                {
                    _databaseService.updateUserExpirationDate( nUserId, _plugin );
                }

                SiteMessageService.setMessage( request, PROPERTY_ACCOUNT_REACTIVATED, null,
                        PROPERTY_ACCOUNT_REACTIVATED_TITLE,
                        AppPropertiesService.getProperty( PROPERTY_MYLUTECE_DEFAULT_REDIRECT_URL ), null,
                        SiteMessage.TYPE_INFO );
            }
        }

        SiteMessageService.setMessage( request, PROPERTY_ERROR_NO_ACCOUNT_TO_REACTIVATE, null,
                PROPERTY_MESSAGE_LABEL_ERROR,
                AppPropertiesService.getProperty( PROPERTY_MYLUTECE_DEFAULT_REDIRECT_URL ), null,
                SiteMessage.TYPE_ERROR );
    }

    /**
     * Get the reset password message
     * @param request The request
     * @throws SiteMessageException The exception thrown to redirect the user to
     *             the message
     */
    public void getMessageResetPassword( HttpServletRequest request ) throws SiteMessageException
    {
        SiteMessageService.setMessage( request, MESSAGE_MUST_CHANGE_PASSWORD, null, MESSAGE_PASSWORD_EXPIRED,
                getResetPasswordUrl( ), null, SiteMessage.TYPE_INFO );
    }

    /**
     * Delete an account and logout user
     * @param request The request
     */
    private void deleteAccount( HttpServletRequest request )
    {
        // Get remote user
        DatabaseUser user = getRemoteUser( request );
        if ( user == null )
        {
            return;
        }

        DatabaseUserHome.remove( user, PluginService.getPlugin( MyLutecePlugin.PLUGIN_NAME ) );
        DatabaseHome.removeGroupsForUser( user.getUserId( ), _plugin );
        DatabaseHome.removeRolesForUser( user.getUserId( ), _plugin );
        MyLuteceUserFieldService.doRemoveUserFields( user.getUserId( ), request, request.getLocale( ) );
        DatabaseUserKeyService.getService( ).removeByIdUser( user.getUserId( ) );
        SecurityService.getInstance( ).logoutUser( request );
    }
}
