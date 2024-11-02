import {
  Redirect,
  Route,
  Switch,
} from "react-router-dom/cjs/react-router-dom.min";
import Home from "./pages/Home";
import Login from "./pages/Login";
import HandleAuthRedirect from "./pages/HandleAuthRedirect";

function App() {
  return (
    <Switch>
      <Route path="/" exact>
        <Redirect to="/home" />
      </Route>
      <Route path="/home">
        <Home />
      </Route>
      <Route path="/login" exact>
        <Login />
      </Route>
      <Route path="/login/oauth2/code/public-client-react-app" exact>
        <HandleAuthRedirect />
      </Route>
    </Switch>
  );
}

export default App;
