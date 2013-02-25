<%@ page errorPage="../../../../ErrorPage.jsp" %>

<jsp:useBean id="databaseJspBean" scope="session" class="fr.paris.lutece.plugins.mylutece.modules.database.authentication.web.DatabaseJspBean" />

<%
	databaseJspBean.init( request, databaseJspBean.RIGHT_MANAGE_DATABASE_USERS ) ;
	String strContent = databaseJspBean.getImportUsersFromFile( request );
%>
<jsp:include page="../../../../AdminHeader.jsp"  flush="true" />

<%= strContent %>

<%@ include file="../../../../AdminFooter.jsp" %>