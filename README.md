#Project: Shack Snack

Overview
Welcome to the Shack Snack Application! This app allows users to browse and purchase a variety of delicious snacks online. The app features a user-friendly interface, secure user authentication, and a robust order management system.

Features
User Registration and Login: Users can create an account and log in to access personalized features.

Snack Catalog: Browse a wide range of snacks with detailed descriptions and pricing.

Shopping Cart: Add snacks to the cart and proceed to checkout.

Order History: View past orders and order details.

User Profile: Manage personal information and view liked snacks and wishlist items.

Installation
Follow these steps to set up the Shack the Snack Application on your local machine:

1. Clone the Repository:
  git clone https://github.com/VictisHankis/shack-snack.git

2. Navigate to the Project Directory:
  cd shack-snack

3. Create a Virtual Environment:
  python -m venv venv

4. Activate the Virtual Environment:
  On Windows:
  venv\Scripts\activate

  On macOS/Linux:
  source venv/bin/activate

5. Set the FLASK_APP Environment Variable:
  On Windows (Command Prompt):
  set FLASK_APP=application/app.py

  On PowerShell:
  $env:FLASK_APP = "application/app.py"

  On macOS/Linux:
  export FLASK_APP=application/app.py

6. Set Up the Database:
  flask db upgrade

7. Run the Application:
  flask run

Troubleshooting: 'flask' Command Not Recognized
If you receive the error message "'flask' is not recognized as an internal or external command, operable program or batch file," follow these additional steps:

1. Verify Flask and Required Packages Installation: Ensure Flask, Flask-Migrate, Flask-WTF, and Flask-SQLAlchemy are installed:
  pip install flask flask-migrate flask-wtf flask_sqlalchemy 

2. Set the FLASK_APP Environment Variable Again:
  On Windows (Command Prompt):
  set FLASK_APP=application/app.py

  On PowerShell:
  $env:FLASK_APP = "application/app.py"

  On macOS/Linux:
  export FLASK_APP=application/app.py

3. Run the Database Commands:
  flask db init
  flask db migrate
  flask db upgrade

4. Run the Application:
  flask run

Usage
1. Open Your Browser: Navigate to http://127.0.0.1:5000.

2. Register an Account: Click on the "Register" link to create a new account.

3. Browse Snacks: Explore the various snacks available in the catalog.

4. Add to Cart: Add your favorite snacks to the shopping cart.

5. Checkout: Proceed to checkout and place your order.

6. View Order History: Access your order history from your profile.

Security Features
#CSRF Protection: Ensures all forms have CSRF tokens to prevent cross-site request forgery.

#Input Validation: User inputs are validated to prevent SQL injection and XSS attacks.

#Access Control: Only authorized users can access specific parts of the application.

Contributing
We welcome contributions to the Snack Shop Application! Please fork the repository and create a pull request with your changes.

Contact
For questions or feedback, please contact vicmansol32@gmail.com, niu.rod2020@gmail.com, or Csoto00110@gmail.com.
