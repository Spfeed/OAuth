import { Fragment, useEffect, useState } from "react";
import axios from "axios";
import { useHistory } from "react-router-dom/cjs/react-router-dom.min";
import { refreshAccessToken } from "../utils/tokenUtils";

const Home = (props) => {
  const [message, setMessage] = useState("");
  const history = useHistory();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get("http://localhost:8081/info-status", {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
        });
        setMessage(response.data);
      } catch (error) {
        if (error.response && error.response.status === 401) {
          //Попытка обновления access токена
          const newAccessToken = await refreshAccessToken();

          if (newAccessToken) {
            //Если токен обновился, то запрос повторяется
            try {
              const response = await axios.get(
                "http://localhost:8081/info-status",
                {
                  headers: {
                    Authorization: `Bearer ${newAccessToken}`,
                  },
                }
              );
              setMessage(response.data);
            } catch (error) {
              console.error("Ошибка при получении данных: ", error);
              //Если снова 401, то перенаправляем на /login
              history.push("/login");
            }
          } else {
            //Если не удалось обновить токен
            history.push("/login");
          }
        } else {
          console.error("Ошибка при получении данных", error);
        }
      }
    };

    fetchData();
  }, [history]);

  return (
    <Fragment>
      <div>{message ? <p>{message}</p> : <p>Загрузка...</p>}</div>
    </Fragment>
  );
};

export default Home;
