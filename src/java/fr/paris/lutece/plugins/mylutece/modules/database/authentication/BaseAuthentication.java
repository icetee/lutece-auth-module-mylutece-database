/*
 * Copyright (c) 2002-2012, Mairie de Paris
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
package fr.paris.lutece.plugins.mylutece.modules.database.authentication;

import fr.paris.lutece.plugins.mylutece.authentication.PortalAuthentication;
import fr.paris.lutece.plugins.mylutece.authentication.logs.ConnectionLog;
import fr.paris.lutece.plugins.mylutece.authentication.logs.ConnectionLogHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.GroupRoleHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.parameter.DatabaseUserParameterHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.DatabasePlugin;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.DatabaseService;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.web.MyLuteceDatabaseApp;
import fr.paris.lutece.plugins.mylutece.service.MyLutecePlugin;
import fr.paris.lutece.portal.service.i18n.I18nService;
import fr.paris.lutece.portal.service.plugin.Plugin;
import fr.paris.lutece.portal.service.plugin.PluginService;
import fr.paris.lutece.portal.service.security.FailedLoginCaptchaException;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;


/**
 * The Class provides an implementation of the inherited abstract class PortalAuthentication based on a database.
 * 
 * @author Mairie de Paris
 * @version 2.0.0
 * 
 * @since Lutece v2.0.0
 */
public class BaseAuthentication extends PortalAuthentication
{
	// //////////////////////////////////////////////////////////////////////////////////////////////
	// Constants
	private static final String AUTH_SERVICE_NAME = AppPropertiesService.getProperty( "mylutece-database.service.name" );
	private static final String PLUGIN_JCAPTCHA = "jcaptcha";

	// PROPERTIES
	private static final String PROPERTY_MAX_ACCESS_FAILED = "access_failures_max";
	private static final String PROPERTY_ACCESS_FAILED_CAPTCHA = "access_failures_captcha";
	private static final String PROPERTY_INTERVAL_MINUTES = "access_failures_interval";

	// Messages properties
	private static final String PROPERTY_MESSAGE_USER_NOT_FOUND_DATABASE = "module.mylutece.database.message.userNotFoundDatabase";
	private static final String CONSTANT_PATH_ICON = "images/local/skin/plugins/mylutece/modules/database/mylutece-database.png";

	/**
	 * Constructor
	 * 
	 */
	public BaseAuthentication( )
	{
		super( );
	}

	/**
	 * Gets the Authentification service name
	 * @return The name of the authentication service
	 */
	public String getAuthServiceName( )
	{
		return AUTH_SERVICE_NAME;
	}

	/**
	 * Gets the Authentification type
	 * @param request The HTTP request
	 * @return The type of authentication
	 */
	public String getAuthType( HttpServletRequest request )
	{
		return HttpServletRequest.BASIC_AUTH;
	}

	/**
	 * This methods checks the login info in the database
	 * 
	 * @param strUserName The username
	 * @param strUserPassword The password
	 * @param request The HttpServletRequest
	 * @return A LuteceUser object corresponding to the login
	 * @throws LoginException The LoginException
	 */
	public LuteceUser login( String strUserName, String strUserPassword, HttpServletRequest request ) throws LoginException
	{
		DatabaseService _databaseService = DatabaseService.getService( );

		Plugin pluginMyLutece = PluginService.getPlugin( MyLutecePlugin.PLUGIN_NAME );
		Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );
		// Creating a record of connections log
		ConnectionLog connectionLog = new ConnectionLog( );
		connectionLog.setIpAddress( request.getRemoteAddr( ) );
		connectionLog.setDateLogin( new java.sql.Timestamp( new java.util.Date( ).getTime( ) ) );

		// Test the number of errors during an interval of minutes
		int nMaxFailed = DatabaseUserParameterHome.getIntegerSecurityParameter( PROPERTY_MAX_ACCESS_FAILED, plugin );
		int nMaxFailedCaptcha = 0;
		int nIntervalMinutes = DatabaseUserParameterHome.getIntegerSecurityParameter( PROPERTY_INTERVAL_MINUTES, plugin );
		boolean bEnableCaptcha = false;

		if ( PluginService.isPluginEnable( PLUGIN_JCAPTCHA ) )
		{
			nMaxFailedCaptcha = DatabaseUserParameterHome.getIntegerSecurityParameter( PROPERTY_ACCESS_FAILED_CAPTCHA, plugin );
		}

		if ( ( nMaxFailed > 0 || nMaxFailedCaptcha > 0 ) && nIntervalMinutes > 0 )
		{
			int nNbFailed = ConnectionLogHome.getLoginErrors( connectionLog, nIntervalMinutes, pluginMyLutece );

			if ( nMaxFailedCaptcha > 0 && nNbFailed >= nMaxFailedCaptcha )
			{
				bEnableCaptcha = true;
			}
			if ( nMaxFailed > 0 && nNbFailed > nMaxFailed )
			{
				if ( bEnableCaptcha )
				{
					throw new FailedLoginCaptchaException( bEnableCaptcha );
				}
				else
				{
					throw new FailedLoginException( );
				}
			}
		}

		Locale locale = request.getLocale( );

		BaseUser user = DatabaseHome.findLuteceUserByLogin( strUserName, plugin, this );

		// Unable to find the user
		if ( ( user == null ) || !_databaseService.isUserActive( strUserName, plugin ) )
		{
			AppLogService.info( "Unable to find user in the database : " + strUserName );
			if ( bEnableCaptcha )
			{
				throw new FailedLoginCaptchaException( I18nService.getLocalizedString( PROPERTY_MESSAGE_USER_NOT_FOUND_DATABASE, locale ), bEnableCaptcha );
			}
			else
			{
				throw new FailedLoginException( I18nService.getLocalizedString( PROPERTY_MESSAGE_USER_NOT_FOUND_DATABASE, locale ) );
			}
		}

		// Check password
		if ( !_databaseService.checkPassword( strUserName, strUserPassword, plugin ) )
		{
			AppLogService.info( "User login : Incorrect login or password" + strUserName );
			if ( bEnableCaptcha )
			{
				throw new FailedLoginCaptchaException( I18nService.getLocalizedString( PROPERTY_MESSAGE_USER_NOT_FOUND_DATABASE, locale ), bEnableCaptcha );
			}
			else
			{
				throw new FailedLoginException( I18nService.getLocalizedString( PROPERTY_MESSAGE_USER_NOT_FOUND_DATABASE, locale ) );
			}
		}

		// Get roles
		List<String> arrayRoles = DatabaseHome.findUserRolesFromLogin( strUserName, plugin );

		if ( !arrayRoles.isEmpty( ) )
		{
			user.setRoles( arrayRoles );
		}

		// Get groups
		List<String> arrayGroups = DatabaseHome.findUserGroupsFromLogin( strUserName, plugin );

		if ( !arrayGroups.isEmpty( ) )
		{
			user.setGroups( arrayGroups );
		}

		// We update the status of the user if his password has become obsolete
		Timestamp passwordMaxValidDate = DatabaseHome.findPasswordMaxValideDateFromLogin( strUserName, plugin );
		if ( passwordMaxValidDate != null && passwordMaxValidDate.getTime( ) < new java.util.Date( ).getTime( ) )
		{
			DatabaseHome.updateResetPasswordFromLogin( strUserName, Boolean.TRUE, plugin );
		}
		int nUserId = DatabaseHome.findUserIdFromLogin( strUserName, plugin );
		_databaseService.updateUserExpirationDate( nUserId, plugin );

		return user;
	}

	/**
	 * This methods logout the user
	 * @param user The user
	 */
	public void logout( LuteceUser user )
	{
	}

	/**
	 * Find users by login
	 * @param request The request
	 * @param strLogin the login
	 * @return DatabaseUser the user corresponding to the login
	 */
	public boolean findResetPassword( HttpServletRequest request, String strLogin )
	{
		Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );
		return DatabaseHome.findResetPasswordFromLogin( strLogin, plugin );
	}

	/**
	 * This method returns an anonymous Lutece user
	 * 
	 * @return An anonymous Lutece user
	 */
	public LuteceUser getAnonymousUser( )
	{
		return new BaseUser( LuteceUser.ANONYMOUS_USERNAME, this );
	}

	/**
	 * Checks that the current user is associated to a given role
	 * @param user The user
	 * @param request The HTTP request
	 * @param strRole The role name
	 * @return Returns true if the user is associated to the role, otherwise false
	 */
	public boolean isUserInRole( LuteceUser user, HttpServletRequest request, String strRole )
	{
		String[] roles = getRolesByUser( user );

		if ( ( roles != null ) && ( strRole != null ) )
		{
			for ( String role : roles )
			{
				if ( strRole.equals( role ) )
				{
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Returns the View account page URL of the Authentication Service
	 * @return The URL
	 */
	public String getViewAccountPageUrl( )
	{
		return MyLuteceDatabaseApp.getViewAccountUrl( );
	}

	/**
	 * Returns the New account page URL of the Authentication Service
	 * @return The URL
	 */
	public String getNewAccountPageUrl( )
	{
		return MyLuteceDatabaseApp.getNewAccountUrl( );
	}

	/**
	 * Returns the Change password page URL of the Authentication Service
	 * @return The URL
	 */
	public String getChangePasswordPageUrl( )
	{
		return MyLuteceDatabaseApp.getChangePasswordUrl( );
	}

	/**
	 * Returns the lost password URL of the Authentication Service
	 * @return The URL
	 */
	public String getLostPasswordPageUrl( )
	{
		return MyLuteceDatabaseApp.getLostPasswordUrl( );
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getLostLoginPageUrl( )
	{
		return MyLuteceDatabaseApp.getLostLoginUrl( );
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getResetPasswordPageUrl( HttpServletRequest request )
	{
		return AppPathService.getBaseUrl( request ) + MyLuteceDatabaseApp.getMessageResetPasswordUrl( );
	}

	/**
	 * Returns all users managed by the authentication service if this feature is available.
	 * @return A collection of Lutece users or null if the service doesn't provide a users list
	 */
	public Collection<LuteceUser> getUsers( )
	{
		Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );

		Collection<BaseUser> baseUsers = DatabaseHome.findDatabaseUsersList( plugin, this );
		Collection<LuteceUser> luteceUsers = new ArrayList<LuteceUser>( );

		for ( BaseUser user : baseUsers )
		{
			luteceUsers.add( user );
		}

		return luteceUsers;
	}

	/**
	 * Returns the user managed by the authentication service if this feature is available.
	 * @param userLogin the user login
	 * @return A Lutece users or null if the service doesn't provide a user
	 */
	public LuteceUser getUser( String userLogin )
	{
		Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );

		BaseUser user = DatabaseHome.findLuteceUserByLogin( userLogin, plugin, this );

		return user;
	}

	/**
	 * get all roles for this user : - user's roles - user's groups roles
	 * 
	 * @param user The user
	 * @return Array of roles
	 */
	public String[] getRolesByUser( LuteceUser user )
	{
		Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );
		Set<String> setRoles = new HashSet<String>( );
		String[] strGroups = user.getGroups( );
		String[] strRoles = user.getRoles( );

		if ( strRoles != null )
		{
			for ( String strRole : strRoles )
			{
				setRoles.add( strRole );
			}
		}

		if ( strGroups != null )
		{
			for ( String strGroupKey : strGroups )
			{
				Collection<String> arrayRolesGroup = GroupRoleHome.findGroupRoles( strGroupKey, plugin );

				for ( String strRole : arrayRolesGroup )
				{
					setRoles.add( strRole );
				}
			}
		}

		String[] strReturnRoles = new String[setRoles.size( )];
		setRoles.toArray( strReturnRoles );

		return strReturnRoles;
	}

	/**
	 * 
	 *{@inheritDoc}
	 */
	public String getIconUrl( )
	{
		return CONSTANT_PATH_ICON;
	}

	/**
	 * 
	 * Returns {@link DatabasePlugin#PLUGIN_NAME}.
	 * @return {@link DatabasePlugin#PLUGIN_NAME}
	 */
	public String getName( )
	{
		return DatabasePlugin.PLUGIN_NAME;
	}

	/**
	 *{@inheritDoc}
	 */
	public String getPluginName( )
	{
		return DatabasePlugin.PLUGIN_NAME;
	}

	/**
	 *{@inheritDoc}
	 */
	@Override
	public void updateDateLastLogin( LuteceUser user, HttpServletRequest request )
	{
		DatabaseService _databaseService = DatabaseService.getService( );
		Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );
		_databaseService.updateUserLastLoginDate( user.getName( ), plugin );
	}
}
