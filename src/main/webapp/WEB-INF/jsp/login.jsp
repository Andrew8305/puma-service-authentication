<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<jsp:include page="includes/header.jsp" />

<div class="container">

	<div class="row">  
		<div class="col-md-12">  
      <h1 class="page-header">Login</h1> 
    </div>
	</div>

  <form:form method="post" class="form-signin" action="proc/login">
    <input type="text" class="form-control" placeholder="Loginname" name="loginName" id="loginName" required autofocus>
    <input type="password" class="form-control" placeholder="Password" name="password" id="password" required>
    <button class="btn btn-lg btn-primary btn-block" type="submit">Log in</button>
  </form:form>
</div>

<!-- 
<div class="container">
	<div style="position: absolute; left: 50%; top: 50%; text-align: center; width:300px; height:265px; margin-left: -150px; margin-top: -132px;">
		<h1>Login</h1>
		<form:form method="post" action="proc/login" class="form-horizontal">
			<div class="control-group">
				<label for="loginName" class="col-sm-2 control-label">Name:</label>
				<div class="controls">
					<input name="loginName" class="form-control" id="loginName"
						placeholder="Login" />
				</div>
			</div>
			<div class="control-group">
				<label for="password" class="col-sm-2 control-label">Password:</label>
				<div class="controls">
					<input name="password" class="form-control" id="password" type="password"
						placeholder="Password" />
				</div>
			</div>
			<div class="control-group">
				<div class="controls">
					<input type="submit" value="Login" class="btn" />
				</div>
			</div>
		</form:form>
	</div>
</div>
-->

<jsp:include page="includes/footer.jsp" />
