<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<jsp:include page="includes/header.jsp" />

<div class="container">
	<div class="row">
		<div class="span8 offset2">

			<h1>Users</h1>
			<form:form method="post" action="add" commandName="test"
				class="form-horizontal">
				<div class="control-group">
					<form:label cssClass="control-label" path="name">Name:</form:label>
					<div class="controls">
						<form:input path="name" />
					</div>
				</div>
				<div class="control-group">
					<div class="controls">
						<input type="submit" value="Add Test" class="btn" />
					</div>
				</div>
			</form:form>
		</div>
	</div>

	<c:if test="${!empty tests}">
		<h3>Users</h3>
		<table class="table table-bordered table-striped">
			<thead>
				<tr>
					<th>Name</th>
					<th>&nbsp;</th>
				</tr>
			</thead>
			<tbody>
				<c:forEach items="${tests}" var="test">
					<tr>
						<td>${test.name}</td>
						<td>
							<form action="delete/${test.id}" method="post">
								<input type="submit" class="btn btn-danger btn-mini"
									value="Delete" />
							</form>
						</td>
					</tr>
				</c:forEach>
			</tbody>
		</table>
	</c:if>
</div>

<jsp:include page="includes/footer.jsp" />
