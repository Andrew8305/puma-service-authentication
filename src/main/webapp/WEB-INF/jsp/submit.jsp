<html>
	<head>
		<script type="text/javascript"></script>
	</head>
	<body onload="sendRedirect()">
		<form id="toSubmit" action="${relayState}" method="post">
			<input type="hidden" id="UserId" name="UserId" value="${userId}">
			<input type="hidden" id="PrimaryTenant" name="PrimaryTenant" value="${primaryTenant}">
			<input type="hidden" id="Tenant" name="Tenant" value="${tenant}">
			<input type="hidden" id="Token" name="Token" value="${token}">
			<input type="hidden" id="attributes" name="attributes" value='${attributes}'>
		</form>
		
		<script>
			function sendRedirect() {
				document.getElementById("toSubmit").submit();
			}
		</script>
	</body>
</html>