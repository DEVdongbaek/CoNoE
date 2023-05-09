import React from "react";
import Layout from "../components/common/layout/Layout.jsx";
import FormPageContainer from "../styles/FormPageContainer.js";
import StyledH3 from "../styles/StyledH3.js";
import Form from "../components/common/form/Form.jsx";
import FORM_DEFAULT from "../constant/FORM_DEFAULT.js";
import FORM_INFO from "../constant/FORM_INFO.js";

function CreateRoom() {
  return (
    <Layout isLoggedIn={true}>
      <FormPageContainer>
        <StyledH3>방 만들기</StyledH3>
        <Form
          onSubmit={(value) => console.log(value)}
          onError={(err) => console.log(err)}
          defaultValues={FORM_DEFAULT.CREATE_ROOM}
          inputInformations={FORM_INFO.CREATE_ROOM}
          buttonLabel="방 만들기"
        />
      </FormPageContainer>
    </Layout>
  );
}

export default CreateRoom;
