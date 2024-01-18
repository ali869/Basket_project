from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/local_basket'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with a secret key for JWT encoding

db = SQLAlchemy(app)
jwt = JWTManager(app)


class Customers(db.Model):
    customer_id = db.Column(db.String(255), primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    telephone = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    basket = db.relationship('Basket', backref='customer', uselist=False)  # Relationship to Basket


class Products(db.Model):
    product_id = db.Column(db.String(255), primary_key=True)
    category = db.Column(db.String(50))
    colour = db.Column(db.String(50))
    size = db.Column(db.String(100), nullable=False)
    price = db.Column(db.DECIMAL(10, 2), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False)
    basket_items = db.relationship('Basket', backref='product')  # Relationship to Basket


class Basket(db.Model):
    basket_id = db.Column(db.String(255), primary_key=True)
    customer_id = db.Column(db.String(255), db.ForeignKey('customers.customer_id'), nullable=False)
    item_id = db.Column(db.String(255), db.ForeignKey('products.product_id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False)


class StripePayments(db.Model):
    payment_id = db.Column(db.String(255), primary_key=True)
    basket_id = db.Column(db.String(255), db.ForeignKey('basket.basket_id'),
                          nullable=False)  # Update foreign key reference
    customer_id = db.Column(db.String(255), db.ForeignKey('customers.customer_id'), nullable=False)
    stripe_payment_intent_id = db.Column(db.String(255))
    amount = db.Column(db.DECIMAL(10, 2), nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    payment_status = db.Column(db.String(50), nullable=True)
    shipping_address_line1 = db.Column(db.String(100), nullable=False)
    shipping_address_line2 = db.Column(db.String(100), nullable=True)
    shipping_address_line3 = db.Column(db.String(100), nullable=True)
    shipping_address_ine4 = db.Column(db.String(100), nullable=True)
    shipping_postcode = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    basket = db.relationship('Basket', backref='payment')


class Orders(db.Model):
    order_id = db.Column(db.String(255), primary_key=True)
    order_status = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False)


@app.route('/products', methods=['POST'])
def create_product():
    data = request.json
    product_id = uuid.uuid4()
    new_product = Products(product_id=product_id, category=data['category'], colour='colour', size=data['size'],
                           price=data['price'], created_at=datetime.datetime.now(), updated_at=datetime.datetime.now())
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'})


@app.route('/products', methods=['GET'])
def get_products():
    try:
        # Query all products from the database
        products = Products.query.all()

        # Convert the product objects to a list of dictionaries
        products_list = [
            {
                'product_id': product.product_id,
                'category': product.category,
                'colour': product.colour,
                'size': product.size,
                'price': float(product.price),  # Convert Decimal to float for JSON serialization
                'created_at': product.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': product.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            for product in products
        ]

        # Return the products as JSON
        return jsonify({'products': products_list})

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        return jsonify({'error': 'An error occurred while fetching products'}), 500


@app.route('/create_basket', methods=['POST'])
@jwt_required()
def create_basket():
    try:
        import pdb; pdb.set_trace()
        current_user = get_jwt_identity()
        user = Customers.query.filter_by(customer_id=current_user).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json.get('products')  # Assuming the payload has a key 'products' containing a list of products
        if not data or not isinstance(data, list):
            return jsonify({'error': 'Invalid payload'}), 400

        # Iterate through the products in the payload and add them to the user's basket
        for product_info in data:
            product_id = product_info.get('product_id')
            quantity = product_info.get('quantity', 1)  # Default quantity is 1

            product = Products.query.get(product_id)
            if not product:
                return jsonify({'error': f'Product with ID {product_id} not found'}), 404

            # Create a new basket item for the user
            basket_item = Basket(
                basket_id=str(uuid.uuid4()),
                customer_id=current_user,
                item_id=product_id,
                quantity=quantity,
                date_created=datetime.datetime.now()
            )

            # Add the basket item to the database
            db.session.add(basket_item)

        # Commit the changes to the database
        db.session.commit()

        return jsonify({'message': 'Products added to the basket successfully'}), 200

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        return jsonify({'error': 'An error occurred while adding products to the basket'}), 500


@app.route('/get_basket', methods=['GET'])
@jwt_required()
def get_basket():
    try:
        current_user = get_jwt_identity()
        user = Customers.query.filter_by(customer_id=current_user).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Retrieve the basket items for the user
        basket_items = Basket.query.filter_by(customer_id=current_user).all()

        # Construct a list of product details in the basket
        basket_details = []
        for basket_item in basket_items:
            product = Products.query.get(basket_item.item_id)
            if product:
                product_details = {
                    'product_id': product.product_id,
                    'category': product.category,
                    'colour': product.colour,
                    'size': product.size,
                    'price': float(product.price),  # Convert Decimal to float for JSON serialization
                    'quantity': basket_item.quantity,
                    'date_added': basket_item.date_created
                }
                basket_details.append(product_details)

        return jsonify({'basket_details': basket_details}), 200

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        return jsonify({'error': 'An error occurred while retrieving basket details'}), 500


# Route to add a product to the user's basket (JWT required)
@app.route('/add_to_basket', methods=['POST'])
@jwt_required()
def add_to_basket():
    try:
        current_user = get_jwt_identity()
        user = Customers.query.filter_by(customer_id=current_user).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)  # Default quantity is 1

        # Check if the product exists
        product = Products.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        # Check if the product is already in the user's basket
        existing_item = Basket.query.filter_by(customer_id=current_user, item_id=product_id).first()

        if existing_item:
            # If the product is already in the basket, update the quantity
            existing_item.quantity += quantity
        else:
            # If the product is not in the basket, add it
            new_basket_item = Basket(
                basket_id=str(uuid.uuid4()),
                customer_id=current_user,
                item_id=product_id,
                quantity=quantity,
                date_created=datetime.datetime.now()
            )
            db.session.add(new_basket_item)

        db.session.commit()

        return jsonify({'message': 'Product added to basket successfully'}), 200

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        return jsonify({'error': 'An error occurred while adding product to basket'}), 500


# Route to remove a product from the user's basket (JWT required)
@app.route('/remove_from_basket', methods=['POST'])
@jwt_required()
def remove_from_basket():
    try:
        current_user = get_jwt_identity()
        user = Customers.query.filter_by(customer_id=current_user).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json
        product_id = data.get('product_id')

        # Check if the product exists
        product = Products.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        # Check if the product is in the user's basket
        basket_item = Basket.query.filter_by(customer_id=current_user, item_id=product_id).first()

        if basket_item:
            # If the product is in the basket, remove it
            db.session.delete(basket_item)
            db.session.commit()
            return jsonify({'message': 'Product removed from basket successfully'}), 200
        else:
            return jsonify({'error': 'Product not found in basket'}), 404

    except Exception as e:
        # Handle exceptions appropriately (e.g., log the error)
        return jsonify({'error': 'An error occurred while removing product from basket'}), 500


# User signup
@app.route('/signup', methods=['POST'])
def signup():
    import pdb;
    pdb.set_trace()
    data = request.json
    first_name = data['first_name']
    last_name = data['last_name']
    date_of_birth = data['date_of_birth']
    email = data['email']
    telephone = data['telephone']
    password = generate_password_hash(data['password'])
    customer_id = str(uuid.uuid4())

    new_user = Customers(customer_id=customer_id, email=email, password_hash=password,
                         first_name=first_name, last_name=last_name, birth_date=date_of_birth,
                         telephone=telephone, created_at=datetime.datetime.now())
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'})


@app.route('/signin', methods=['POST'])
def signin():
    import pdb;
    pdb.set_trace()
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Find the user by email
    user = Customers.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        # If the user is found and the password is correct
        access_token = create_access_token(identity=user.customer_id)
        return jsonify(access_token=access_token)

    # If the user or password is incorrect
    return jsonify({'message': 'Invalid credentials'}), 401


# Create product with JWT authorization


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)
