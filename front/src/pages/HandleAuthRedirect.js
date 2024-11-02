import axios from "axios";
import { useEffect } from "react";
import { useHistory } from "react-router-dom/cjs/react-router-dom.min";

const HandleAuthRedirect = () => {
  const history = useHistory();

  useEffect(() => {
    console.log("HandleAuthRedirect выполнен");
    const exchangeCodeForToken = async () => {
      const params = new URLSearchParams(window.location.search);
      const code = params.get("code");
      console.log("Authorization code:", code);
      const codeVerifier = localStorage.getItem("code_verifier");
      console.log("Code Verifier:", codeVerifier);

      if (!code || !codeVerifier) {
        console.error("Ошибка: код авторизации или code_verifier отсутствуют!");
        return;
      }
      try {
        console.log("Sending request with parameters:", {
          code,
          grant_type: "authorization_code",
          client_id: "public-client-react-app",
          redirect_uri:
            "http://localhost:3000/login/oauth2/code/public-client-react-app",
          code_verifier: codeVerifier,
        });
        const response = await axios.post(
          "http://localhost:8080/oauth2/token",
          {
            code: code,
            grant_type: "authorization_code",
            client_id: "public-client-react-app",
            redirect_uri:
              "http://localhost:3000/login/oauth2/code/public-client-react-app",
            code_verifier: codeVerifier,
          },
          {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Accept: "*/*",
            },
          }
        );

        console.log("Response data:", response.data);

        if (response.status === 200) {
          // Сохранение access и refresh токена в localStorage
          localStorage.setItem("access_token", response.data.access_token);
          localStorage.setItem("refresh_token", response.data.refresh_token);
          history.push("/home");
        } else {
          console.error("Ошибка при получении токена:", response);
        }
      } catch (error) {
        console.error("Ошибка при обмене кода на токен: ", error);
      }
    };

    exchangeCodeForToken();
  }, [history]);

  return <div>Обработка перенаправления...</div>;
};

export default HandleAuthRedirect;
