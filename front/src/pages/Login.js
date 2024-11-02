import { useEffect } from "react";
import { useHistory } from "react-router-dom/cjs/react-router-dom.min";
import {
  generateCodeChallenge,
  generateCodeVerifier,
} from "../utils/pkceUtils";

const Login = () => {
  const history = useHistory();

  useEffect(() => {
    const handleLogin = async () => {
      try {
        // Генерация code_challenge и code_verifier
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = await generateCodeChallenge(codeVerifier);

        // Сохранение code_verifier в sessionStorage
        localStorage.setItem("code_verifier", codeVerifier);

        // Формирование URL для запроса к серверу авторизации
        const redirectUri = encodeURIComponent(
          "http://localhost:3000/login/oauth2/code/public-client-react-app"
        );
        const authUrl = `http://localhost:8080/oauth2/authorize?response_type=code&client_id=public-client-react-app&scope=openid&redirect_uri=${redirectUri}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

        // Перенаправление пользователя на сервер авторизации
        window.location.href = authUrl;
      } catch (error) {
        console.error("Ошибка в процессе аутентификации:", error);
      }
    };

    handleLogin();
  }, [history]);

  return (
    <div>
      <h2>
        Пожалуйста, подождите, мы перенаправляем вас на страницу авторизации...
      </h2>
    </div>
  );
};

export default Login;
