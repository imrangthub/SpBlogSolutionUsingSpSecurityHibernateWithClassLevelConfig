<%@ page isELIgnored="false"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<jsp:include page="/WEB-INF/views/_partial/_header.jsp" />
   <div class="container">    
    <!-- Example row of columns -->
      <div class="row">
        <div class="col-md-8 col-md-offset-2">
        <div style="hight:50px; margin-top:20px;">
        <h4>Edit Post</h4>
        <span class="pull-right">
        
          <c:if test="${not empty message}">
		    <div  class="alert alert-${css} alert-dismissible well" role="alert">
			<button type="button" class="close" data-dismiss="alert" aria-label="Close">
				<span aria-hidden="true">×</span>
			</button>
			<strong>${message}</strong>
		    </div>
		</c:if>

         </span>
        </div>
            <div class="row">
             <div class="col-md-8 col-md-offset-2">
               <form action="/SpBlogSolutionUsingSpSecurityHibernateWithClassLevelConfig/post/update" method="POST" enctype="multipart/form-data">
				      <input type="hidden" id="current_image" name="current_image" value="${singlePost.feature_image }"/>
				      		      <input type="hidden" id="id" name="id" value="${singlePost.id }"/>
				  <div class="form-group">
				    <label for="exampleInputEmail1">Title</label>
				    <input type="text" class="form-control" id="title" name="title" value="${singlePost.title }" placeholder="Post title">
				  </div>
				  <div class="form-group">
				    <label for="exampleInputPassword1">Post body</label>
			         <textarea class="form-control" name="body" rows="3">${singlePost.body }</textarea>
				  </div>
				    <div class="form-group" id="currentImgDiv">
					    <label for="exampleInputPassword1">Current Image</label><br>
						<c:choose>
							<c:when test="${empty singlePost.feature_image }">
								<h4>NO IMAGE</h4>
							</c:when>
							<c:otherwise>
								<img
									src="<c:url value="/resources/imgFolder/${singlePost.feature_image}"/>"
									width="200px" height="150px" />
													  <button id="removeImageBtn" type="button" class="btn btn-warning">Remove Image</button>
							</c:otherwise>
						</c:choose>
				   </div>
				   <div class="form-group">
				    <label for="exampleInputFile">File input</label>
				    <input type="file" id="file" name="file">
				    <p class="help-block">Post image file must be .jpg or .png file.</p>
				   </div>
				  <button type="reset" class="btn btn-warning">Cancel</button>
				  <button type="submit" class="btn btn-success">Submit</button>
				</form>
             </div>
            </div>
        </div>
      </div>     
	<jsp:include page="/WEB-INF/views/_partial/_footerMenu.jsp" />
</div>
<!-- /container -->
<jsp:include page="/WEB-INF/views/_partial/_footer.jsp" />

     <script>
            $(document).ready(function(){
            	$('#removeImageBtn').click(function(){
            		$('#current_image').val("");
            		$('#currentImgDiv').remove();
            	});
            });
        </script>
