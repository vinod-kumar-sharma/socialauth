<%@page
	import="de.deltatree.social.web.filter.api.language.SASFRepositoryType"%>
<%@page
	import="de.deltatree.social.web.filter.api.language.SASFRepositoryConsts"%>
<%@page import="java.util.List"%>
<%@page import="de.deltatree.social.web.filter.api.SASFHelper"%>
<%@page
	import="de.deltatree.social.web.filter.api.language.SASFRepositoryLanguage"%>
<%@page import="de.deltatree.social.web.filter.api.SASFStaticHelper"%>

<%
	SASFHelper helper = SASFStaticHelper.getHelper(request);
	SASFRepositoryLanguage srl = SASFRepositoryLanguage.GERMAN;
	List<String> ids = helper.getMgr().getSocialAuthProviderIds();
	int count = ids.size();
%>

<html>
<head>
<title>social auth login</title>
<style type="text/css">
a:link {
	color: black;
	text-decoration: none;
}

a:visited {
	color: black;
	text-decoration: none;
}

a:focus {
	color: black;
	text-decoration: none;
}

a:hover {
	color: black;
	text-decoration: none;
}

a:active {
	color: black;
	text-decoration: none;
}
</style>
</head>
<body>
	<form action="<%=helper.getServletMain()%>">
		<table height="97%" width="100%">
			<tr>
				<td>&nbsp;</td>
				<td align="center" valign="middle" width="750">
					<fieldset>
						<legend>
							Login mit OpenId (<a href="http://de.wikipedia.org/wiki/OpenID"
								style="text-decoration: underline;" target="_blank">WIKI</a>)
						</legend>
						<table cellpadding="4" cellspacing="4">
							<tr>
								<td colspan="<%=count%>" align="left"><b>Bitte
										w&auml;hlen Sie Ihren OpenId Provider durch Klick auf eines
										der nachfolgenden Icons:</b></td>
							</tr>
							<tr>
								<%
									for (String id : ids) {
										String href = helper.getServletMain()
												+ "?id="
												+ helper.getRep().getText(srl,
														SASFRepositoryConsts.SECURITY_OPENID_PROVIDER,
														id, SASFRepositoryType.ID);
										String img_src = helper.getRep().getText(srl,
												SASFRepositoryConsts.SECURITY_OPENID_PROVIDER, id,
												SASFRepositoryType.IMAGE);
										String alt = helper.getRep().getText(srl,
												SASFRepositoryConsts.SECURITY_OPENID_PROVIDER, id,
												SASFRepositoryType.DESCRIPTION);
										String title = helper.getRep().getText(srl,
												SASFRepositoryConsts.SECURITY_OPENID_PROVIDER, id,
												SASFRepositoryType.NAME);
								%>
								<td align="center">
									<table cellpadding="0" cellspacing="0" border="0" height="66">
										<tr>
											<td align="center" valign="top"><a href="<%=href%>"><img
													src="<%=img_src%>" alt="<%=alt%>" title="<%=title%>"
													border="0"></img> </a></td>
										</tr>
										<tr>
											<td align="center" valign="bottom"><i><a
													href="<%=href%>"><%=title%></a> </i></td>
										</tr>
									</table>
								</td>
								<%
									}
								%>
							</tr>
							<tr>
								<td colspan="<%=count%>" align="center"><b>...oder
										tippen Sie Ihre OpenId im nachfolgenden Eingabefeld ein:</b></td>
							</tr>
							<tr>
								<td colspan="<%=count%>" align="center"><input type="text"
									value="http://" name="id" size="55" /> <input type="submit"
									value="login" />
								</td>
							</tr>
						</table>
					</fieldset>

					<table cellpadding="4" cellspacing="4">
						<tr>
							<td colspan="2" align="center"><b>...oder m&ouml;chten
									Sie anonym bleiben?</b></td>
						</tr>
						<tr>
							<td align="right"><a
								href="<%=helper.getServletMain()%>?id=anonymous&"><img
									src="anonymous.png" alt="anonymous" title="login als anonymous"
									border="0"> </a>
							</td>
							<td align="left"><i> Nach dem Klick auf den Button
									werden Sie als<br> anonymous angemeldet, hierbei sollte
									Ihnen bewu&szlig;t sein,<br> dass Sie Ihre Informationen
									mit allen anderen teilen, die sich<br> ebenfalls so
									anmelden </i>
							</td>
						</tr>
					</table>
				</td>
				<td>&nbsp;</td>
			</tr>
		</table>
	</form>
</body>
</html>