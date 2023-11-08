from flask import render_template, request, jsonify, flash, redirect, url_for, session
import json
import app

# Load data from data.json
with open('data.json', 'r') as json_file:
    data = json.load(json_file)

def delete_value(tag):
    for intent in data['intents']:
        if intent['tag'] == tag:
            data['intents'].remove(intent)
            with open('data.json', 'w') as json_file:
                json.dump(data, json_file, indent=4)
            flash(f'Value for tag "{tag}" deleted successfully', 'success')
            return jsonify({'message': f'Value for tag "{tag}" deleted successfully'})
    flash(f'Tag "{tag}" not found', 'error')
    return jsonify({'error': f'Tag "{tag}" not found'})


def display_items():
    if 'user_id' not in session:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))

    # User is authenticated and has an API key, proceed to the /create_tag route
    return render_template('Creating_tags.html', data=data)


def create_tag():
    if request.method == 'POST':
        # Add the new tag data to the existing JSON
        data['intents'].append(request.json)
        print(request.json)
        # Update the JSON file
        with open('data.json', 'w') as json_file:
            json.dump(data, json_file, indent=4)
        flash('New value created successfully', 'success')
    return jsonify({'message': 'New value created successfully'})

def update_value(tag):
    # Find the intent with the given tag
    intent = None
    for i in data['intents']:
        if i['tag'] == tag:
            intent = i
            break

    if intent is None:
        flash(f'Tag "{tag}" not found', 'error')
        return jsonify({'error': f'Tag "{tag}" not found'})

    if request.method == 'POST':
        # Get the updated values from the form
        data['intents'].remove(intent)
        data['intents'].append(request.json)
       
        # Update the JSON file
        with open('data.json', 'w') as json_file:
            json.dump(data, json_file, indent=4)

        flash(f'Value for tag "{tag}" updated successfully', 'success')

    return jsonify({'message': 'Value updated successfully'})

if __name__ == '__main__':
    app.run(debug=True)
