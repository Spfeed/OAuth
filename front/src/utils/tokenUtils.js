import axios from "axios";

export const refreshAccessToken = async () => {
  const refreshToken = localStorage.getItem("refresh_token");
  console.log("refresh-token: ", refreshToken);

  if (refreshToken) {
    try {
      const response = await axios.post(
        "http://localhost:8080/oauth2/token",
        {
          grant_type: "refresh_token",
          client_id: "public-client-react-app",
          redirect_uri:
            "http://localhost:3000/login/oauth2/code/public-client-react-app",
          refresh_token: refreshToken,
        },
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "*/*",
          },
        }
      );

      //Сохранение нового access-токена в localStorage
      console.log("Response data: ", response.data);
      localStorage.setItem("access_token", response.data.access_token);
      return response.data.access_token; //Возврат нового токена
    } catch (error) {
      console.error("Ошибка при обновлении токена: ", error);
      return null;
    }
  }

  return null; //Если refresh-токена нет
};
