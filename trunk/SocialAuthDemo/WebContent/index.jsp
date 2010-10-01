<html>
	<head>
		<title>SocialAuth Demo</title>
		<script>
			function validate(obj){
				var val = obj.id.value;
				if(trimString(val).length <= 0){
					alert("Please enter OpenID URL");
					return false;
				}else{
					return true;
				}
			}
			function trimString(tempStr)
			{
			   return tempStr.replace(/^\s*|\s*$/g,"");
			}
		</script>
	</head>
	<body>
		<table cellpadding="10" cellspacing="10" align="center">
			<tr><td colspan="5"><h3 align="center">Welcome to Social Auth Demo</h3></td></tr>
			<tr><td colspan="5"><p align="center">Please click on any icon.</p></td></tr>
			<tr>
				<td><a href="socialAuth.do?id=facebook"><img src="images/facebook_icon.png" border="0"></img></a></td>
				<td><a href="socialAuth.do?id=twitter"><img src="images/twitter_icon.png" border="0"></img></a></td>
			
				<td><a href="socialAuth.do?id=google"><img src="images/gmail-icon.jpg" border="0"></img></a></td>
				<td><a href="socialAuth.do?id=yahoo"><img src="images/yahoomail_icon.jpg" border="0"></img></a></td>
			
				<td><a href="socialAuth.do?id=hotmail"><img src="images/hotmail.jpeg" border="0"></img></a></td>
			</tr>
			<tr>
				<td colspan="5" align="center">
					<form action="socialAuth.do" onsubmit="return validate(this);">
						or enter OpenID url: <input type="text" value="" name="id"/>
						<input type="submit" value="Submit"/> 
					</form>
				</td>
			</tr>
			
		</table>
	</body>
</html>