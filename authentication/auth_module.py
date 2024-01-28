from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import stripe
import os

stripe.api_key = "sk_test_51LCj9uKZSvaz9gvrL2PW6BjZZzKxUHM0PHwvlZ8sQMkuA59snhCyg1TUwkiN2Gn21S67MkXwxu9v6sOhdpJHWCy200JQlYOhYU"

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/local_basket2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'Secret_key_shh676767'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['BASE_URL'] = 'http://localhost:5000'

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
    image_path = db.Column(db.String(255), nullable=True)  # New column for image path
    updated_at = db.Column(db.DateTime, nullable=False)
    basket_items = db.relationship('Basket', backref='product')  # Relationship to Basket


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


class Basket(db.Model):
    basket_id = db.Column(db.String(255), primary_key=True)
    customer_id = db.Column(db.String(255), db.ForeignKey('customers.customer_id'), nullable=False)
    item_id = db.Column(db.String(255), db.ForeignKey('products.product_id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False)


class StripePayments(db.Model):
    payment_id = db.Column(db.String(255), primary_key=True)
    customer_id = db.Column(db.String(255), db.ForeignKey('customers.customer_id'), nullable=False)
    stripe_payment_intent_id = db.Column(db.String(255))
    amount = db.Column(db.DECIMAL(10, 2), nullable=True)
    currency = db.Column(db.String(10), nullable=True)
    payment_status = db.Column(db.String(50), nullable=True)
    stripe_customer_id = db.Column(db.String(50), nullable=True)
    shipping_address_line1 = db.Column(db.String(100), nullable=False)
    shipping_address_line2 = db.Column(db.String(100), nullable=True)
    shipping_address_line3 = db.Column(db.String(100), nullable=True)
    shipping_address_ine4 = db.Column(db.String(100), nullable=True)
    shipping_postcode = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)


class Orders(db.Model):
    order_id = db.Column(db.String(255), primary_key=True)
    order_status = db.Column(db.String(50), nullable=True)
    customer_id = db.Column(db.String(255), db.ForeignKey('customers.customer_id'), nullable=False)
    payment_method_id = db.Column(db.String(255), db.ForeignKey('stripe_payments.payment_id'), nullable=False)
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
        products = Products.query.all()

        products_list = [
            {
                'product_id': product.product_id,
                'category': product.category,
                'colour': product.colour,
                'size': product.size,
                'price': float(product.price),
                'created_at': product.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': product.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'image_path': url_for('static', filename='uploads/' + os.path.basename(
                    product.image_path)) if product.image_path else ''
            }
            for product in products
        ]

        return jsonify({'products': products_list})

    except Exception as e:
        return jsonify({'error': 'An error occurred while fetching products'}), 500


@app.route('/create_basket', methods=['POST'])
@jwt_required()
def create_basket():
    try:
        current_user = get_jwt_identity()
        user = Customers.query.filter_by(customer_id=current_user).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json.get('products')
        if not data or not isinstance(data, list):
            return jsonify({'error': 'Invalid payload'}), 400

        for product_info in data:
            product_id = product_info.get('product_id')
            quantity = product_info.get('quantity', 1)  # Default quantity is 1

            product = Products.query.get(product_id)
            if not product:
                return jsonify({'error': f'Product with ID {product_id} not found'}), 404

            basket_item = Basket(
                basket_id=str(uuid.uuid4()),
                customer_id=current_user,
                item_id=product_id,
                quantity=quantity,
                date_created=datetime.datetime.now()
            )

            db.session.add(basket_item)

        db.session.commit()

        return jsonify({'message': 'Products added to the basket successfully'}), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred while adding products to the basket'}), 500


@app.route('/get_basket', methods=['GET'])
@jwt_required()
def get_basket():
    try:
        current_user = get_jwt_identity()
        user = Customers.query.filter_by(customer_id=current_user).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        basket_items = Basket.query.filter_by(customer_id=current_user).all()

        basket_details = []
        for basket_item in basket_items:
            product = Products.query.get(basket_item.item_id)
            if product:
                product_details = {
                    'product_id': product.product_id,
                    'category': product.category,
                    'colour': product.colour,
                    'size': product.size,
                    'price': float(product.price),
                    'quantity': basket_item.quantity,
                    'date_added': basket_item.date_created,
                    'image_path': url_for('static', filename='uploads/' + os.path.basename(
                        product.image_path)) if product.image_path else ''
                }
                basket_details.append(product_details)

        return jsonify({'basket_details': basket_details}), 200

    except Exception as e:
        return jsonify({'error': 'An error occurred while retrieving basket details'}), 500


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

        product = Products.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        existing_item = Basket.query.filter_by(customer_id=current_user, item_id=product_id).first()

        if existing_item:
            existing_item.quantity += quantity
        else:
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
        return jsonify({'error': 'An error occurred while adding product to basket'}), 500


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

        product = Products.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        basket_item = Basket.query.filter_by(customer_id=current_user, item_id=product_id).first()

        if basket_item:
            db.session.delete(basket_item)
            db.session.commit()
            return jsonify({'message': 'Product removed from basket successfully'}), 200
        else:
            return jsonify({'error': 'Product not found in basket'}), 404

    except Exception as e:
        return jsonify({'error': 'An error occurred while removing product from basket'}), 500


@app.route('/signup', methods=['POST'])
def signup():
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
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = Customers.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.customer_id)
        return jsonify(access_token=access_token)

    return jsonify({'message': 'Invalid credentials'}), 401


def create_stripe_user(p_method, email):
    try:
        customer = stripe.Customer.create(
            payment_method=p_method,
            email=email
        )

        return 'success', customer

    except Exception as e:
        return None, str(e)


def user_payment_method(stripe_user, card=None):
    payment_methods = stripe.PaymentMethod.list(
        customer=stripe_user,
        type='card'
    )
    if payment_methods:
        if card:
            result = dict()
            result['last4'] = payment_methods.data[0]['card']['last4']
            result['exp_month'] = payment_methods.data[0]['card']['exp_month']
            result['exp_year'] = payment_methods.data[0]['card']['exp_year']
            result['brand'] = payment_methods.data[0]['card']['brand']
            return result
        return payment_methods.data[0].id


def create_stripe_intent(customer, payment_method, amount):
    try:
        intent = stripe.PaymentIntent.create(
            customer=customer,
            payment_method=payment_method,
            currency='gbp',
            amount=int(float(amount) * 100),
            off_session=True,
            confirm=True
        )

        return 'success', intent
    except Exception as e:
        return None, str(e)


def make_transaction(customer):
    pm_id = user_payment_method(customer)
    success, response = create_stripe_intent(customer, pm_id, 500)
    return success, response


@app.route('/add-payment-method', methods=['POST'])
@jwt_required()
def add_payment_method():
    data = request.json
    p_method = data.get('payment_method_id', None)
    if not p_method:
        return jsonify({'message': 'Payment method id is required.'}), 400
    current_user = get_jwt_identity()
    user = Customers.query.filter_by(customer_id=current_user).first()
    success, customer = create_stripe_user(p_method, user.email)
    if not success:
        return jsonify({'success': False, 'message': f'{customer.split(": ")[-1]}'}, 400)
    success, stripe_response = make_transaction(customer.id)
    if success:
        basket_items = Basket.query.filter_by(customer_id=current_user).all()
        total_price = 0.0

        for basket_item in basket_items:
            product = Products.query.get(basket_item.item_id)
            if product:
                total_price += float(product.price) * basket_item.quantity
        payment_intent = stripe.PaymentIntent.create(
            amount=int(total_price),
            currency='gbp',
            payment_method_types=['card'],
            receipt_email=user.email
        )
        new_payment_id = uuid.uuid4()
        new_payment = StripePayments(
            payment_id=new_payment_id,
            customer_id=user.customer_id,
            stripe_payment_intent_id=payment_intent['id'],
            amount=total_price,
            stripe_customer_id=customer.id,
            currency='gbp',
            payment_status='APPROVED',
            shipping_address_line1='Test address',
            shipping_postcode='test_code',
            created_at=datetime.datetime.now()
        )
        db.session.add(new_payment)
        db.session.commit()
        new_order = Orders(order_id=uuid.uuid4(), order_status='APPROVED', customer_id=user.customer_id,
                           payment_method_id=new_payment_id, created_at=datetime.datetime.now())
        db.session.add(new_order)
        db.session.commit()
        basket_items = Basket.query.filter_by(customer_id=current_user).all()
        for basket in basket_items:
            db.session.delete(basket)
            db.session.commit()
        return jsonify({'success': True, 'message': 'stripe payment intent', 'payment_intent': payment_intent,
                        'user_email': str(user.email), 'customer_id': customer.id,
                        'status_message': 'Payment Created successfully.'}, 200)

    return jsonify({'message': 'Failed to create Payment Method'}, 400)


@app.route('/get-order-details', methods=['GET'])
@jwt_required()
def order_details():
    try:
        current_user = get_jwt_identity()
        user = Customers.query.filter_by(customer_id=current_user).first()
        all_orders = list()
        get_payments = StripePayments.query.filter_by(customer_id=current_user)
        for get_payment in get_payments:
            response_dict = {}
            if get_payment.payment_status == 'APPROVED':
                get_order = Orders.query.filter_by(customer_id=current_user).first()
                response_dict['order_id'] = get_order.order_id
                response_dict['order_status'] = get_order.order_status
                response_dict['order_created_at'] = get_order.created_at
            response_dict['payment_id'] = get_payment.payment_id
            response_dict['amount'] = int(get_payment.amount)
            response_dict['payment_status'] = get_payment.payment_status
            response_dict['shipping_address_line1'] = get_payment.shipping_address_line1
            response_dict['shipping_address_line2'] = get_payment.shipping_address_line2
            response_dict['shipping_address_line3'] = get_payment.shipping_address_line3
            response_dict['shipping_postcode'] = get_payment.shipping_postcode
            all_orders.append(response_dict)
        return jsonify({'Order details': all_orders}, 200)
    except Exception as e:
        return jsonify({'error': f'Failed to get order details because {str(e)}'}, 400)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)
