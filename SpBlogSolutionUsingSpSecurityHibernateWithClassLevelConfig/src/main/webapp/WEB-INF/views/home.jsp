<%@ page isELIgnored="false"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<jsp:include page="/WEB-INF/views/_partial/_header.jsp" />
<div class="container">
	<!-- Example row of columns -->
	<div class="row">
		<div class="row">
			<c:if test="${!empty lastPost}">
				<div class="col-md-8 col-md-offset-2">
					<div class="col-md-12">
						<div id="imgDiv" class="well">
							<c:choose>
									 <c:when test="${empty lastPost.feature_image }"><h4>There is no Image for this post</h4></c:when>
									 <c:otherwise>
									 <img src="<c:url value="/resources/imgFolder/${lastPost.feature_image }"/>"
								width="600px" height="400px" />
									 </c:otherwise>
							</c:choose>
							
						</div>
						<h2>${lastPost.title }</h2>
						<p>${lastPost.body}
						<p>
							<a class="btn btn-default" href="#" role="button">View
								details &raquo;</a>
						</p>
					</div>
				</div>

			</c:if>

		</div>
		<div class="row">

			<c:forEach items="${postList }" var="post">
				<div class="col-md-4">
					<div id="imgDiv" class="well">
							<c:choose>
									 <c:when test="${empty post.feature_image }"><h4>NO IMAGE</h4></c:when>
									 <c:otherwise>
								<img
							src="<c:url value="/resources/imgFolder/${post.feature_image }"/>"
							width="200px" height="150px" />
									 </c:otherwise>
							</c:choose>
						
					</div>
					<h2>${post.title }</h2>
					<p>${post.body }
					<p>
						<a class="btn btn-default" href="#" role="button">View details
							&raquo;</a>
					</p>
				</div>
			</c:forEach>
		</div>
	</div>
	<jsp:include page="/WEB-INF/views/_partial/_footerMenu.jsp" />
</div>
<!-- /container -->
<jsp:include page="/WEB-INF/views/_partial/_footer.jsp" />