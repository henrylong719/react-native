import { FC } from 'react';
import { View, StyleSheet, Text } from 'react-native';

interface Props {}

const Signin: FC<Props> = (props) => {
  return (
    <View style={styles.container}>
      <Text>Sign in</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {},
});

export default Signin;
