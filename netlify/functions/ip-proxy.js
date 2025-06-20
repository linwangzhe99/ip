// Netlify Function for IP analysis proxy
// This function acts as a proxy to hide API keys and handle CORS

exports.handler = async (event, context) => {
  // Set CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: '',
    };
  }

  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  try {
    // Parse the request body
    const requestBody = JSON.parse(event.body);
    
    // Validate the request
    if (!requestBody || !Array.isArray(requestBody)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid request body. Expected array of IP queries.' }),
      };
    }

    // Limit the number of IPs to prevent abuse
    if (requestBody.length > 50) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Too many IPs. Maximum 50 allowed.' }),
      };
    }

    // Make request to ip-api.com
    const response = await fetch('http://ip-api.com/batch?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(data),
    };

  } catch (error) {
    console.error('Error in ip-proxy function:', error);
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Internal server error',
        message: 'Failed to analyze IP addresses'
      }),
    };
  }
};