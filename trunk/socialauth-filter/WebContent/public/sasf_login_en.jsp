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
							Login with OpenId (<a href="http://en.wikipedia.org/wiki/OpenID"
								style="text-decoration: underline;" target="_blank">WIKI</a>)
						</legend>
						<table cellpadding="4" cellspacing="4">
							<tr>
								<td colspan="<%=count%>" align="left"><b>please choose
										your OpenId provider:</b></td>
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
								<td colspan="<%=count%>" align="center"><b>...or tip in
										your OpenId:</b></td>
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
							<td colspan="2" align="center"><b>...or you want to be
									anonymous?</b></td>
						</tr>
						<tr>
							<td align="right"><a
								href="<%=helper.getServletMain()%>?id=anonymous&"><img
									src="anonymous.png" alt="anonymous" title="login as anonymous"
									border="0"></img> </a>
							</td>
							<td align="left"><i>Keep in mind that as "anonymous" you are sharing all
									your data </i></td>
						</tr>
					</table>
				</td>
				<td>&nbsp;</td>
			</tr>
		</table>
	</form>
</body>
</html>