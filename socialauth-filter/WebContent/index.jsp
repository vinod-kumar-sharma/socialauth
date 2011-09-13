<%@page import="de.deltatree.social.web.filter.api.SASFUser"%>
<%@page import="de.deltatree.social.web.filter.api.SASFStaticHelper"%>
<%@page import="de.deltatree.social.web.filter.api.SASFHelper"%>
<%
	String id = "not logged in";
	String functionalId = "not logged in";
	SASFHelper helper = SASFStaticHelper.getHelper(request);
	if (helper != null) {
		SASFUser user = helper.getUser();
		if (user != null) {
			id = user.getId();
			functionalId = user.getFunctionalName();
		}
	}
%>

<html>
<head>
<title>login example</title>
</head>
<body>
	<table width="100%" height="97%">
		<tr>
			<td align="center" valign="middle">
				<table border="1" cellpadding="8" cellspacing="0">
					<tr>
						<td>Unique id</td>
						<td>:</td>
						<td><%=id%></td>
					</tr>
					<tr>
						<td>Functional name</td>
						<td>:</td>
						<td><%=functionalId%></td>
					</tr>
				</table> <a href="<%=helper.getServletLogoff()%>">logoff</a></td>
		</tr>
	</table>
</body>
</html>