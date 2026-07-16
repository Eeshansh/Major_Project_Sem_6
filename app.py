from flask import Flask, render_template, request

from utils.rule_engine import analyze_url

from utils.ml_model import predict_url


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])

def home():

    result = None

    ml_result = None

    if request.method == "POST":

        url = request.form["url"]

        # Rule-based analysis

        result = analyze_url(url)

        # ML analysis

        ml_result = predict_url(url)

        phishing_probability = ml_result[
            "phishing_probability"
        ]

        # Hybrid moderation logic

        if result["risk_score"] > 0:

            if phishing_probability > 80:

                result["risk_score"] += 10

                result["reasons"].append(
                    "ML model detected strong phishing patterns"
                )

            elif phishing_probability > 60:

                result["risk_score"] += 5

                result["reasons"].append(
                    "ML model detected moderate suspicious behavior"
                )

        # Final verdict recalculation

        if result["risk_score"] >= 80:

            result["verdict"] = "Phishing"

        elif result["risk_score"] >= 50:

            result["verdict"] = "Extremely Suspicious"

        elif result["risk_score"] >= 30:

            result["verdict"] = "Suspicious"
        
        else:

            result["verdict"] = "Legitimate"

        print("\nRULE RESULT:\n")

        print(result)

        print("\nML RESULT:\n")

        print(ml_result)

    return render_template(

        "index.html",

        result=result,

        ml_result=ml_result
    )


if __name__ == "__main__":

     app.run(host="0.0.0.0", port=5000, debug=True) 